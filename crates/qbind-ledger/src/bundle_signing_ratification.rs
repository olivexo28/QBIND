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
    MlDsa44SignatureSuite, SignatureSuite, ML_DSA_44_PUBLIC_KEY_SIZE, ML_DSA_44_SIGNATURE_SIZE,
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
pub const BUNDLE_SIGNING_RATIFICATION_DOMAIN_V1: &[u8] = b"QBIND:BUNDLE-SIGNING-RATIFICATION:v1";

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
            let hi = hex_nibble(bytes[i])
                .ok_or_else(|| serde::de::Error::custom("non-hex byte in hex_vec field"))?;
            let lo = hex_nibble(bytes[i + 1])
                .ok_or_else(|| serde::de::Error::custom("non-hex byte in hex_vec field"))?;
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
            + 4
            + r.chain_id.len()
            + 4
            + r.environment.tag().len()
            + 32
            + 4
            + r.authority_root_fingerprint.len()
            + 1
            + 4
            + r.bundle_signing_public_key.len()
            + 4
            + r.bundle_signing_public_key_fingerprint.len(),
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
    BundleSigningKeyFingerprintMismatch { expected: String, got: String },

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
    if find_root(
        &authority.bundle_signing_authority_roots,
        fingerprint,
        suite_id,
    )
    .is_some()
    {
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
// Run 105 — Enforcement layer for non-mutating validation surfaces
// ===========================================================================

/// Run 105 — environment-policy escape hatch for legacy DevNet/TestNet
/// callers that have not yet migrated to genesis-bound ratification.
///
/// Production policy:
///
///   * MainNet → MUST be [`RatificationEnforcementPolicy::Strict`].
///     Local config alone is NEVER sufficient on MainNet.
///   * TestNet → SHOULD be `Strict`. The
///     [`RatificationEnforcementPolicy::AllowLegacyUnratified`] policy
///     is permitted only when the operator has explicitly opted in via
///     CLI/config, and MUST be logged loudly.
///   * DevNet → MAY be `AllowLegacyUnratified` for local development
///     workflows; the absence of a ratification object is then surfaced
///     as a [`RatificationEnforcementOutcome::LegacyUnratifiedAccepted`]
///     verdict (NOT silently treated as ratified).
///
/// The enforcer NEVER converts `AllowLegacyUnratified` into a verified
/// outcome — operators see the precise verdict in logs and metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatificationEnforcementPolicy {
    /// Ratification is mandatory. Missing ratification fails closed
    /// with [`RatificationEnforcementFailure::Missing`]. This is the
    /// only policy permitted on MainNet.
    Strict,
    /// Ratification is optional on this surface. If supplied, it MUST
    /// verify; if absent, the call returns
    /// [`RatificationEnforcementOutcome::LegacyUnratifiedAccepted`]
    /// rather than failing. The caller is responsible for logging and
    /// for refusing this outcome on MainNet (the enforcer also refuses
    /// `AllowLegacyUnratified` on MainNet — defense in depth).
    AllowLegacyUnratified,
}

/// Outcome of [`enforce_bundle_signing_key_ratification`] on a successful
/// path. Never returned for an explicit failure; failures are typed
/// [`RatificationEnforcementFailure`] values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RatificationEnforcementOutcome {
    /// A ratification object was supplied AND verified by the Run 103
    /// verifier AND its `bundle_signing_public_key` matches the
    /// candidate trust-bundle's signing key.
    Ratified(RatifiedBundleSigningKey),
    /// No ratification object was supplied AND the policy is
    /// [`RatificationEnforcementPolicy::AllowLegacyUnratified`] (and
    /// the runtime environment is NOT MainNet). Callers MUST log this
    /// verdict — it is explicitly NOT a "passed" outcome and is never
    /// available on MainNet.
    LegacyUnratifiedAccepted {
        /// SHA3-256 fingerprint of the locally-configured bundle-signing
        /// key, lowercase hex. Carried so the operator log can name the
        /// key that was accepted under the legacy policy.
        bundle_signing_public_key_fingerprint: String,
    },
}

/// Run 105 — typed failure reasons for the enforcement layer.
///
/// Maps cleanly to operator log lines and to error variants in
/// downstream surfaces (`TrustBundleError`, `ReloadCheckError`,
/// `PeerCandidateRejection`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RatificationEnforcementFailure {
    /// MainNet was supplied with `AllowLegacyUnratified` policy.
    /// Refused unconditionally — defense in depth against caller bugs.
    LegacyUnratifiedRefusedOnMainnet,
    /// MainNet/TestNet (under [`RatificationEnforcementPolicy::Strict`])
    /// requires a ratification object, but none was supplied. The
    /// candidate bundle is refused before any mutation side effect.
    Missing {
        environment: RatificationEnvironment,
        /// SHA3-256 fingerprint of the candidate bundle's signing key
        /// (lowercase hex), so the operator log can name what was
        /// refused without exposing key bytes.
        bundle_signing_public_key_fingerprint: String,
    },
    /// The supplied ratification object failed Run 103 verification.
    /// Wraps the precise typed reason. The candidate bundle is refused
    /// before any mutation side effect.
    Verifier(RatificationFailure),
    /// The supplied ratification verified, but its
    /// `bundle_signing_public_key` does NOT match the candidate
    /// trust-bundle's signing key. This catches the case where an
    /// operator supplies a *valid* ratification for some *other* key.
    RatifiesDifferentKey {
        /// Fingerprint of the key authorised by the ratification.
        ratified_fingerprint: String,
        /// Fingerprint of the key the candidate trust bundle was
        /// actually signed by.
        candidate_fingerprint: String,
    },
    /// The genesis authority block does not contain ANY
    /// `bundle_signing_authority_roots` entries. Without a ratifying
    /// authority surface MainNet/TestNet cannot enforce ratification —
    /// fail closed rather than silently accept any local key.
    NoBundleSigningAuthorityConfigured {
        environment: RatificationEnvironment,
    },
}

impl std::fmt::Display for RatificationEnforcementFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RatificationEnforcementFailure::LegacyUnratifiedRefusedOnMainnet => write!(
                f,
                "bundle-signing ratification enforcement refused: legacy unratified policy is not \
                 permitted on MainNet (Run 105 invariant; MainNet always requires ratification)"
            ),
            RatificationEnforcementFailure::Missing {
                environment,
                bundle_signing_public_key_fingerprint,
            } => write!(
                f,
                "bundle-signing ratification missing: environment={} requires a ratification \
                 object for bundle-signing key {} (Run 105 strict enforcement)",
                environment.tag(),
                bundle_signing_public_key_fingerprint
            ),
            RatificationEnforcementFailure::Verifier(e) => write!(f, "{}", e),
            RatificationEnforcementFailure::RatifiesDifferentKey {
                ratified_fingerprint,
                candidate_fingerprint,
            } => write!(
                f,
                "bundle-signing ratification authorises a different key: ratified={} candidate={}",
                ratified_fingerprint, candidate_fingerprint
            ),
            RatificationEnforcementFailure::NoBundleSigningAuthorityConfigured { environment } => {
                write!(
                    f,
                    "bundle-signing ratification cannot be enforced: genesis authority block \
                     contains zero bundle_signing_authority_roots on environment={} (Run 105 \
                     refuses to silently accept any local signing key in this configuration)",
                    environment.tag()
                )
            }
        }
    }
}

impl std::error::Error for RatificationEnforcementFailure {}

impl From<RatificationFailure> for RatificationEnforcementFailure {
    fn from(e: RatificationFailure) -> Self {
        RatificationEnforcementFailure::Verifier(e)
    }
}

/// Run 105 — inputs to [`enforce_bundle_signing_key_ratification`].
///
/// All fields are required so the enforcer never falls back to ambient
/// state. Callers compute / supply them explicitly from their existing
/// runtime context.
pub struct RatificationEnforcementInputs<'a> {
    /// Optional ratification object (parsed from a sidecar JSON file or
    /// equivalent operator-supplied source). `None` triggers the
    /// `Missing` / `LegacyUnratifiedAccepted` policy branch.
    pub ratification: Option<&'a BundleSigningRatification>,
    /// Genesis-bound authority block (Run 101/104). The enforcer
    /// consults `bundle_signing_authority_roots` only.
    pub authority: &'a GenesisAuthorityConfig,
    /// Expected runtime chain id.
    pub expected_chain_id: &'a str,
    /// Expected runtime environment policy.
    pub expected_environment: NetworkEnvironmentPolicy,
    /// Canonical genesis hash the runtime computed (Run 102).
    pub expected_genesis_hash: &'a GenesisHash,
    /// Bundle-signing public key actually used to sign the candidate
    /// trust bundle. Used to bind the verified ratification to the
    /// concrete key the loader accepted: a ratification authorising
    /// some *other* key is refused as `RatifiesDifferentKey`.
    pub candidate_bundle_signing_public_key: &'a [u8],
    /// Per-surface enforcement policy. MainNet MUST pass `Strict`.
    /// `AllowLegacyUnratified` is refused on MainNet by the enforcer
    /// itself — defense in depth.
    pub policy: RatificationEnforcementPolicy,
}

/// Run 105 — non-mutating ratification enforcement entry point.
///
/// Used by trust-bundle validation surfaces (startup preflight,
/// reload-check, peer-candidate-check). Returns
/// [`RatificationEnforcementOutcome`] on a clean accept verdict and
/// [`RatificationEnforcementFailure`] on any fail-closed condition.
///
/// The function is pure: it neither reads nor writes any global state,
/// touches no files, and has no side effects beyond returning a typed
/// outcome. Callers MUST run this BEFORE any sequence write, root
/// merge, live trust swap, session eviction, sequence commit, or
/// rebroadcast/propagation acceptance.
///
/// # Decision matrix
///
/// | Policy / Env | ratification supplied | not supplied |
/// |--------------|-----------------------|--------------|
/// | `Strict` / MainNet | verified+matched → `Ratified` (else fail closed) | `Missing` |
/// | `Strict` / TestNet | verified+matched → `Ratified` (else fail closed) | `Missing` |
/// | `Strict` / DevNet  | verified+matched → `Ratified` (else fail closed) | `Missing` |
/// | `AllowLegacyUnratified` / MainNet | **always refused** (`LegacyUnratifiedRefusedOnMainnet`) | **always refused** (same) |
/// | `AllowLegacyUnratified` / TestNet | verified+matched → `Ratified` (else fail closed) | `LegacyUnratifiedAccepted` |
/// | `AllowLegacyUnratified` / DevNet  | verified+matched → `Ratified` (else fail closed) | `LegacyUnratifiedAccepted` |
///
/// In every row, transport-root authority and unknown roots fail
/// closed via the underlying Run 103 verifier (`TransportRootNotAllowed`,
/// `UnknownAuthorityRoot`).
pub fn enforce_bundle_signing_key_ratification<'a>(
    inputs: RatificationEnforcementInputs<'a>,
) -> Result<RatificationEnforcementOutcome, RatificationEnforcementFailure> {
    let env = RatificationEnvironment::from_policy(inputs.expected_environment);
    let candidate_fp = sha3_256_hex(inputs.candidate_bundle_signing_public_key);

    // 0. Defense-in-depth: refuse legacy-unratified on MainNet under any
    //    code path, even if the caller passed it by mistake.
    if matches!(
        inputs.policy,
        RatificationEnforcementPolicy::AllowLegacyUnratified
    ) && matches!(env, RatificationEnvironment::Mainnet)
    {
        return Err(RatificationEnforcementFailure::LegacyUnratifiedRefusedOnMainnet);
    }

    // 1. Strict surface that has zero bundle-signing authority roots
    //    cannot enforce ratification — fail closed rather than silently
    //    accept any local key. (DevNet `AllowLegacyUnratified` may
    //    still proceed via the explicit legacy branch below, since the
    //    operator opted in.)
    if matches!(inputs.policy, RatificationEnforcementPolicy::Strict)
        && inputs.authority.bundle_signing_authority_roots.is_empty()
    {
        return Err(
            RatificationEnforcementFailure::NoBundleSigningAuthorityConfigured { environment: env },
        );
    }

    match inputs.ratification {
        None => {
            // 2a. Missing ratification under strict policy: fail closed.
            match inputs.policy {
                RatificationEnforcementPolicy::Strict => {
                    Err(RatificationEnforcementFailure::Missing {
                        environment: env,
                        bundle_signing_public_key_fingerprint: candidate_fp,
                    })
                }
                RatificationEnforcementPolicy::AllowLegacyUnratified => {
                    // 2b. Legacy DevNet/TestNet: explicit non-failure
                    //     verdict that callers MUST surface in logs.
                    Ok(RatificationEnforcementOutcome::LegacyUnratifiedAccepted {
                        bundle_signing_public_key_fingerprint: candidate_fp,
                    })
                }
            }
        }
        Some(ratification) => {
            // 3. Run 103 verifier — single source of truth for the
            //    crypto / chain / env / genesis / authority-root
            //    binding. Any failure surfaces precisely.
            let ratified = verify_bundle_signing_key_ratification(RatificationVerifierInputs {
                ratification,
                authority: inputs.authority,
                expected_chain_id: inputs.expected_chain_id,
                expected_environment: inputs.expected_environment,
                expected_genesis_hash: inputs.expected_genesis_hash,
            })?;

            // 4. Bind the verified ratification to the concrete
            //    bundle-signing key the loader accepted. Without this
            //    check an operator could supply a valid ratification
            //    for some *other* key and have a bundle signed by a
            //    different key still pass.
            if ratified.public_key.as_slice() != inputs.candidate_bundle_signing_public_key {
                return Err(RatificationEnforcementFailure::RatifiesDifferentKey {
                    ratified_fingerprint: ratified.fingerprint.clone(),
                    candidate_fingerprint: candidate_fp,
                });
            }

            Ok(RatificationEnforcementOutcome::Ratified(ratified))
        }
    }
}

// ===========================================================================
// Run 130 — Ratification v2 schema, preimage, and verifier
// ===========================================================================

// ---------------------------------------------------------------------------
// v2 domain tag and version constant
// ---------------------------------------------------------------------------

/// Domain separator for the v2 bundle-signing-key ratification preimage.
///
/// Distinct from the v1 domain tag
/// [`BUNDLE_SIGNING_RATIFICATION_DOMAIN_V1`] so that no v1 preimage can
/// be confused with a v2 preimage under any input combination.
pub const BUNDLE_SIGNING_RATIFICATION_DOMAIN_V2: &[u8] = b"QBIND:BUNDLE-SIGNING-RATIFICATION:v2";

/// Schema version for v2 ratification objects. Run 130 = `2`.
pub const BUNDLE_SIGNING_RATIFICATION_VERSION_V2: u32 = 2;

// ---------------------------------------------------------------------------
// v2 lifecycle action
// ---------------------------------------------------------------------------

/// The lifecycle action carried by a v2 ratification object.
///
/// The action is included in the canonical preimage so that `ratify`,
/// `rotate`, and `revoke` objects produce different digests even when all
/// other fields are identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BundleSigningRatificationV2Action {
    /// Initial ratification of a new bundle-signing key by an authority root.
    Ratify,
    /// Rotation from one bundle-signing key to another; binds the previous
    /// key fingerprint and the previous ratification digest for chain linking.
    Rotate,
    /// Revocation of a bundle-signing key; binds revocation reason and scope.
    Revoke,
}

impl BundleSigningRatificationV2Action {
    /// Stable one-byte encoding used in the canonical preimage.
    ///
    /// `Ratify = 0`, `Rotate = 1`, `Revoke = 2`. These values are fixed
    /// by Run 130 and must never be reassigned.
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Ratify => 0,
            Self::Rotate => 1,
            Self::Revoke => 2,
        }
    }

    /// Lowercase ASCII tag used in log messages and operator tooling.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Ratify => "ratify",
            Self::Rotate => "rotate",
            Self::Revoke => "revoke",
        }
    }
}

// ---------------------------------------------------------------------------
// v2 ratification object
// ---------------------------------------------------------------------------

/// Run 130 — v2 bundle-signing-key ratification object.
///
/// Extends the v1 [`BundleSigningRatification`] model with:
///
/// * `authority_policy_version` — authority governance policy version;
/// * `authority_root_suite_id` — explicit suite for the authority root (may
///   differ from the target-key suite in future evolutions);
/// * `target_bundle_signing_key_suite_id` — explicit suite for the target key;
/// * `authority_domain_sequence` — per-authority-domain monotonic counter
///   (sequences start at 1; 0 is invalid);
/// * `key_lifecycle_action` — `ratify`, `rotate`, or `revoke`;
/// * `previous_key_fingerprint` / `previous_ratification_digest` — rotation
///   chain linking (required for `rotate`, must be absent for `ratify`);
/// * `valid_from_epoch` / `valid_until_epoch` — optional validity window;
/// * `revocation_reason` / `capabilities_scope` — revocation metadata
///   (at least one must be present for `revoke`).
///
/// The `signature` field is the ML-DSA-44 signature over
/// `sha3_256(v2_canonical_preimage(self))`.
///
/// Run 130 does NOT wire v2 into production enforcement surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleSigningRatificationV2 {
    /// Schema version. MUST equal [`BUNDLE_SIGNING_RATIFICATION_VERSION_V2`]
    /// (= 2). v1 objects are not accepted by the v2 verifier and vice versa.
    pub schema_version: u32,

    /// Environment tag this ratification is bound to.
    pub environment: RatificationEnvironment,

    /// Chain identifier this ratification is bound to.
    pub chain_id: String,

    /// Canonical genesis hash this ratification is bound to.
    pub genesis_hash: GenesisHash,

    /// Authority governance policy version. Included in the signed material
    /// so that a policy change invalidates all older ratification objects.
    pub authority_policy_version: u32,

    /// SHA3-256 fingerprint (lowercase hex) of the authority root that signed
    /// this ratification. Looked up in
    /// [`GenesisAuthorityConfig::bundle_signing_authority_roots`]; never in
    /// `pqc_transport_roots`.
    pub authority_root_fingerprint: String,

    /// PQC suite identifier of the authority root's key. Run 130 accepts only
    /// [`GENESIS_AUTHORITY_SUITE_ML_DSA_44`] (= 100).
    pub authority_root_suite_id: GenesisAuthoritySuiteId,

    /// SHA3-256 fingerprint (lowercase hex) of the target bundle-signing key
    /// being authorised, rotated to, or revoked.
    pub target_bundle_signing_key_fingerprint: String,

    /// PQC suite identifier of the target bundle-signing key. Run 130 accepts
    /// only ML-DSA-44 (= 100) for the target key as well.
    pub target_bundle_signing_key_suite_id: GenesisAuthoritySuiteId,

    /// Full public key bytes of the target bundle-signing key.
    ///
    /// For ML-DSA-44 this MUST be exactly [`ML_DSA_44_PUBLIC_KEY_SIZE`]
    /// (1312) bytes. Carried in full so that downstream consumers do not
    /// need an extra resolution step.
    #[serde(with = "hex_vec")]
    pub target_bundle_signing_public_key: Vec<u8>,

    /// Per-authority-domain monotonic sequence number for this ratification.
    ///
    /// The authority domain is `(environment, chain_id, genesis_hash,
    /// authority_root_fingerprint)`. Sequences must be strictly increasing
    /// within one domain; 0 is rejected as invalid.
    pub authority_domain_sequence: u64,

    /// Lifecycle action: `ratify`, `rotate`, or `revoke`.
    pub key_lifecycle_action: BundleSigningRatificationV2Action,

    /// Fingerprint of the key being rotated away from.
    ///
    /// Required when `key_lifecycle_action == Rotate`; MUST be absent for
    /// `Ratify` (presence of this field for a `Ratify` action is refused
    /// with [`RatificationV2Failure::UnexpectedRotateFieldsForRatify`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_key_fingerprint: Option<String>,

    /// SHA3-256 digest (lowercase hex, 64 chars) of the previous ratification
    /// object, for chain linking.
    ///
    /// Required when `key_lifecycle_action == Rotate`; MUST be absent for
    /// `Ratify`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_ratification_digest: Option<String>,

    /// Optional epoch from which this ratification is valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from_epoch: Option<u64>,

    /// Optional epoch at which this ratification expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until_epoch: Option<u64>,

    /// Human-readable revocation reason. At least one of `revocation_reason`
    /// or `capabilities_scope` MUST be present when
    /// `key_lifecycle_action == Revoke`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_reason: Option<String>,

    /// Revocation scope (e.g. `"all"`, `"signing-only"`). At least one of
    /// `revocation_reason` or `capabilities_scope` MUST be present when
    /// `key_lifecycle_action == Revoke`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities_scope: Option<String>,

    /// ML-DSA-44 signature over `sha3_256(v2_canonical_preimage(self))`,
    /// produced by the authority root's private key.
    #[serde(with = "hex_vec")]
    pub signature: Vec<u8>,
}

// ---------------------------------------------------------------------------
// v2 canonical preimage and digest
// ---------------------------------------------------------------------------

/// Compute the deterministic, domain-separated v2 signing preimage.
///
/// Layout (all integers big-endian, all variable-length fields
/// length-prefixed with a `u32` byte count, optional fields preceded by a
/// `u8` presence flag `0x00` or `0x01`):
///
/// ```text
/// BUNDLE_SIGNING_RATIFICATION_DOMAIN_V2
/// u32  schema_version
/// u32  len(environment_tag)             | environment_tag
/// u32  len(chain_id)                    | chain_id
/// 32   genesis_hash
/// u32  authority_policy_version
/// u32  len(authority_root_fingerprint)  | authority_root_fingerprint
/// u8   authority_root_suite_id
/// u32  len(target_key_fingerprint)      | target_key_fingerprint
/// u8   target_key_suite_id
/// u32  len(target_key_pk)               | target_key_pk (raw bytes, NOT hex)
/// u64  authority_domain_sequence
/// u8   key_lifecycle_action             (0=ratify, 1=rotate, 2=revoke)
/// u8   has_previous_key_fp
///   [u32 len(previous_key_fp) | previous_key_fp]   (if has=1)
/// u8   has_previous_ratification_digest
///   [u32 len(previous_digest_hex) | previous_digest_hex]  (if has=1)
/// u8   has_revocation_reason
///   [u32 len(revocation_reason) | revocation_reason]  (if has=1)
/// u8   has_valid_from_epoch
///   [u64 valid_from_epoch]  (if has=1)
/// u8   has_valid_until_epoch
///   [u64 valid_until_epoch]  (if has=1)
/// u8   has_capabilities_scope
///   [u32 len(capabilities_scope) | capabilities_scope]  (if has=1)
/// ```
///
/// The `signature` field is intentionally NOT included.
/// Changing **any** security-relevant field produces different bytes.
pub fn ratification_v2_signing_preimage(v: &BundleSigningRatificationV2) -> Vec<u8> {
    let env_tag = v.environment.tag().as_bytes();
    let mut buf: Vec<u8> =
        Vec::with_capacity(256 + v.chain_id.len() + v.target_bundle_signing_public_key.len());

    buf.extend_from_slice(BUNDLE_SIGNING_RATIFICATION_DOMAIN_V2);
    buf.extend_from_slice(&v.schema_version.to_be_bytes());
    encode_length_prefixed_bytes(&mut buf, env_tag);
    encode_length_prefixed_bytes(&mut buf, v.chain_id.as_bytes());
    buf.extend_from_slice(&v.genesis_hash);
    buf.extend_from_slice(&v.authority_policy_version.to_be_bytes());
    encode_length_prefixed_bytes(&mut buf, v.authority_root_fingerprint.as_bytes());
    buf.push(v.authority_root_suite_id);
    encode_length_prefixed_bytes(&mut buf, v.target_bundle_signing_key_fingerprint.as_bytes());
    buf.push(v.target_bundle_signing_key_suite_id);
    encode_length_prefixed_bytes(&mut buf, &v.target_bundle_signing_public_key);
    buf.extend_from_slice(&v.authority_domain_sequence.to_be_bytes());
    buf.push(v.key_lifecycle_action.as_byte());

    // Optional / lifecycle-specific fields — each guarded by a u8 presence flag.
    encode_optional_string(&mut buf, v.previous_key_fingerprint.as_deref());
    encode_optional_string(&mut buf, v.previous_ratification_digest.as_deref());
    encode_optional_string(&mut buf, v.revocation_reason.as_deref());

    if let Some(epoch) = v.valid_from_epoch {
        buf.push(1u8);
        buf.extend_from_slice(&epoch.to_be_bytes());
    } else {
        buf.push(0u8);
    }
    if let Some(epoch) = v.valid_until_epoch {
        buf.push(1u8);
        buf.extend_from_slice(&epoch.to_be_bytes());
    } else {
        buf.push(0u8);
    }
    encode_optional_string(&mut buf, v.capabilities_scope.as_deref());

    buf
}

fn encode_optional_string(buf: &mut Vec<u8>, opt: Option<&str>) {
    if let Some(s) = opt {
        buf.push(1u8);
        encode_length_prefixed_bytes(buf, s.as_bytes());
    } else {
        buf.push(0u8);
    }
}

/// SHA3-256 digest of [`ratification_v2_signing_preimage`].
///
/// This is exactly the digest signed and verified under the ML-DSA-44
/// [`SignatureSuite`] adapter for v2 objects.
pub fn canonical_ratification_v2_digest(v: &BundleSigningRatificationV2) -> [u8; 32] {
    qbind_hash::sha3_256(&ratification_v2_signing_preimage(v))
}

// ---------------------------------------------------------------------------
// v2 verifier
// ---------------------------------------------------------------------------

/// Success result of [`verify_bundle_signing_key_ratification_v2`].
///
/// Carries the target key identity and the bound monotonic metadata so that
/// callers cannot accidentally drop the sequence/action binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatifiedBundleSigningKeyV2 {
    /// Full ML-DSA-44 public key bytes of the ratified/rotated/revoked
    /// bundle-signing key.
    pub public_key: Vec<u8>,
    /// Lowercase hex SHA3-256 fingerprint of `public_key`.
    pub fingerprint: String,
    /// PQC suite id of the target key (Run 130 = ML-DSA-44 = 100).
    pub suite_id: GenesisAuthoritySuiteId,
    /// Lowercase hex fingerprint of the authority root that signed this.
    pub authority_root_fingerprint: String,
    /// Authority governance policy version at time of ratification.
    pub authority_policy_version: u32,
    /// Per-authority-domain monotonic sequence bound into this ratification.
    pub authority_domain_sequence: u64,
    /// Lifecycle action this ratification implements.
    pub key_lifecycle_action: BundleSigningRatificationV2Action,
}

/// Typed failure reasons returned by
/// [`verify_bundle_signing_key_ratification_v2`].
///
/// Every variant is precise enough to drive a fail-closed operator log
/// message without any "invalid object" catch-all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RatificationV2Failure {
    /// `schema_version` is not [`BUNDLE_SIGNING_RATIFICATION_VERSION_V2`].
    UnsupportedSchemaVersion { got: u32, expected: u32 },

    /// `environment` does not match the runtime's expected environment.
    WrongEnvironment {
        expected: RatificationEnvironment,
        got: RatificationEnvironment,
    },

    /// `chain_id` does not match the runtime's expected chain id.
    ChainMismatch { expected: String, got: String },

    /// `genesis_hash` does not match the canonical genesis hash for this
    /// runtime.
    GenesisHashMismatch {
        expected: GenesisHash,
        got: GenesisHash,
    },

    /// No `bundle_signing_authority_roots` entry matches
    /// `authority_root_fingerprint` / `authority_root_suite_id`.
    AuthorityRootUnknown { fingerprint: String },

    /// The fingerprint resolves to a `pqc_transport_root` — transport roots
    /// MUST NOT authorise bundle-signing keys.
    TransportRootNotAllowed { fingerprint: String },

    /// `authority_root_suite_id` is not accepted (only ML-DSA-44 = 100).
    AuthoritySuiteUnsupported { suite_id: GenesisAuthoritySuiteId },

    /// The matched authority root carries only a short SHA3-256 fingerprint;
    /// full public-key bytes are required for signature verification.
    AuthorityKeyMaterialUnavailable {
        fingerprint: String,
        suite_id: GenesisAuthoritySuiteId,
        got_hex_len: usize,
        required_hex_len: usize,
    },

    /// The matched authority root's `public_key_hex` is malformed (non-hex,
    /// wrong length, or fingerprint mismatch).
    AuthorityKeyMaterialMalformed {
        fingerprint: String,
        suite_id: GenesisAuthoritySuiteId,
        reason: String,
    },

    /// The authority root's key-fingerprint computed from the resolved public
    /// key does not match the `authority_root_fingerprint` declared in the
    /// ratification object. (Defense-in-depth check for canonical fingerprint
    /// format.)
    AuthorityFingerprintMismatch { declared: String, derived: String },

    /// `target_bundle_signing_key_suite_id` is not accepted (only ML-DSA-44).
    TargetKeySuiteUnsupported { suite_id: GenesisAuthoritySuiteId },

    /// `target_bundle_signing_public_key` has the wrong length for the
    /// declared target suite.
    MalformedTargetPublicKey {
        suite_id: GenesisAuthoritySuiteId,
        got_len: usize,
        expected_len: usize,
    },

    /// `target_bundle_signing_key_fingerprint` does not equal
    /// `sha3_256_hex(target_bundle_signing_public_key)`.
    TargetKeyFingerprintMismatch { expected: String, got: String },

    /// `authority_domain_sequence` is zero (sequences start at 1).
    ///
    /// Note: for a field that is entirely absent from JSON/wire input the
    /// deserialiser would fail before the verifier is called; this variant
    /// covers the case where the field is present but carries an invalid
    /// value.
    MissingAuthorityDomainSequence,

    /// `authority_domain_sequence` is otherwise invalid. Currently fires
    /// only for value 0 (same condition as `MissingAuthorityDomainSequence`
    /// is kept separate for forward-compatibility with future constraints).
    InvalidAuthorityDomainSequence { got: u64 },

    /// `key_lifecycle_action` is absent. Not currently reachable via the
    /// typed Rust API (the field is non-optional); retained as a typed
    /// variant for the wire/serde boundary in future evolution.
    MissingLifecycleAction,

    /// `key_lifecycle_action` carries an unrecognized discriminant.
    /// Not currently reachable via the typed Rust enum; retained for
    /// wire/serde boundaries.
    InvalidLifecycleAction,

    /// `key_lifecycle_action == Rotate` but `previous_key_fingerprint` is
    /// absent.
    MissingPreviousKeyForRotate,

    /// `key_lifecycle_action == Rotate` but `previous_ratification_digest`
    /// is absent.
    MissingPreviousDigestForRotate,

    /// `previous_ratification_digest` is present but is not a 64-character
    /// lowercase hex string (32 bytes).
    MalformedPreviousDigest { reason: String },

    /// `key_lifecycle_action == Revoke` but neither `revocation_reason` nor
    /// `capabilities_scope` is present.
    MissingRevocationFieldsForRevoke,

    /// `key_lifecycle_action == Ratify` but rotation-only fields
    /// (`previous_key_fingerprint` and/or `previous_ratification_digest`)
    /// are present, which is a protocol violation.
    UnexpectedRotateFieldsForRatify,

    /// The ML-DSA-44 signature failed PQC verification.
    SignatureInvalid,

    /// `signature` has the wrong length for the declared suite.
    MalformedSignature {
        suite_id: GenesisAuthoritySuiteId,
        got_len: usize,
        expected_len: usize,
    },
}

impl std::fmt::Display for RatificationV2Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RatificationV2Failure::UnsupportedSchemaVersion { got, expected } => write!(
                f,
                "ratification v2: schema_version {got} unsupported (expected {expected})"
            ),
            RatificationV2Failure::WrongEnvironment { expected, got } => write!(
                f,
                "ratification v2: environment mismatch: expected {:?} got {:?}",
                expected, got
            ),
            RatificationV2Failure::ChainMismatch { expected, got } => write!(
                f,
                "ratification v2: chain_id mismatch: expected '{expected}' got '{got}'"
            ),
            RatificationV2Failure::GenesisHashMismatch { .. } => write!(
                f,
                "ratification v2: genesis_hash does not match runtime canonical genesis hash"
            ),
            RatificationV2Failure::AuthorityRootUnknown { fingerprint } => write!(
                f,
                "ratification v2: authority_root_fingerprint '{fingerprint}' not in genesis bundle_signing_authority_roots"
            ),
            RatificationV2Failure::TransportRootNotAllowed { fingerprint } => write!(
                f,
                "ratification v2: refused: fingerprint '{fingerprint}' resolves to pqc_transport_root, which cannot authorise bundle-signing keys"
            ),
            RatificationV2Failure::AuthoritySuiteUnsupported { suite_id } => write!(
                f,
                "ratification v2: authority_root_suite_id {suite_id} not accepted (only ML-DSA-44 = {GENESIS_AUTHORITY_SUITE_ML_DSA_44})"
            ),
            RatificationV2Failure::AuthorityKeyMaterialUnavailable {
                fingerprint, suite_id, got_hex_len, required_hex_len,
            } => write!(
                f,
                "ratification v2: authority root '{fingerprint}' (suite {suite_id}) carries only a {got_hex_len}-hex fingerprint; {required_hex_len}-hex PQC public key required"
            ),
            RatificationV2Failure::AuthorityKeyMaterialMalformed { fingerprint, suite_id, reason } => write!(
                f,
                "ratification v2: authority root '{fingerprint}' (suite {suite_id}) public_key_hex malformed: {reason}"
            ),
            RatificationV2Failure::AuthorityFingerprintMismatch { declared, derived } => write!(
                f,
                "ratification v2: authority_root_fingerprint declared='{declared}' does not match derived='{derived}'"
            ),
            RatificationV2Failure::TargetKeySuiteUnsupported { suite_id } => write!(
                f,
                "ratification v2: target_bundle_signing_key_suite_id {suite_id} not accepted (only ML-DSA-44 = {GENESIS_AUTHORITY_SUITE_ML_DSA_44})"
            ),
            RatificationV2Failure::MalformedTargetPublicKey { suite_id, got_len, expected_len } => write!(
                f,
                "ratification v2: target_bundle_signing_public_key length {got_len} invalid for suite {suite_id} (expected {expected_len})"
            ),
            RatificationV2Failure::TargetKeyFingerprintMismatch { expected, got } => write!(
                f,
                "ratification v2: target key fingerprint mismatch: sha3_256_hex expected={expected} got={got}"
            ),
            RatificationV2Failure::MissingAuthorityDomainSequence => write!(
                f,
                "ratification v2: authority_domain_sequence is missing or zero (sequences start at 1)"
            ),
            RatificationV2Failure::InvalidAuthorityDomainSequence { got } => write!(
                f,
                "ratification v2: authority_domain_sequence={got} is invalid (must be >= 1)"
            ),
            RatificationV2Failure::MissingLifecycleAction => write!(
                f,
                "ratification v2: key_lifecycle_action is missing"
            ),
            RatificationV2Failure::InvalidLifecycleAction => write!(
                f,
                "ratification v2: key_lifecycle_action carries an unrecognized discriminant"
            ),
            RatificationV2Failure::MissingPreviousKeyForRotate => write!(
                f,
                "ratification v2: key_lifecycle_action=rotate requires previous_key_fingerprint but it is absent"
            ),
            RatificationV2Failure::MissingPreviousDigestForRotate => write!(
                f,
                "ratification v2: key_lifecycle_action=rotate requires previous_ratification_digest but it is absent"
            ),
            RatificationV2Failure::MalformedPreviousDigest { reason } => write!(
                f,
                "ratification v2: previous_ratification_digest is malformed: {reason}"
            ),
            RatificationV2Failure::MissingRevocationFieldsForRevoke => write!(
                f,
                "ratification v2: key_lifecycle_action=revoke requires at least one of revocation_reason or capabilities_scope"
            ),
            RatificationV2Failure::UnexpectedRotateFieldsForRatify => write!(
                f,
                "ratification v2: key_lifecycle_action=ratify must not carry rotation-only fields (previous_key_fingerprint / previous_ratification_digest)"
            ),
            RatificationV2Failure::SignatureInvalid => write!(
                f,
                "ratification v2: signature failed ML-DSA-44 PQC verification"
            ),
            RatificationV2Failure::MalformedSignature { suite_id, got_len, expected_len } => write!(
                f,
                "ratification v2: signature length {got_len} invalid for suite {suite_id} (expected {expected_len})"
            ),
        }
    }
}

impl std::error::Error for RatificationV2Failure {}

/// Inputs to [`verify_bundle_signing_key_ratification_v2`].
pub struct RatificationV2VerifierInputs<'a> {
    /// v2 Ratification object under test.
    pub ratification: &'a BundleSigningRatificationV2,
    /// Genesis authority block from the runtime's authoritative genesis.
    pub authority: &'a GenesisAuthorityConfig,
    /// Expected chain id (from runtime).
    pub expected_chain_id: &'a str,
    /// Expected environment policy (from runtime).
    pub expected_environment: NetworkEnvironmentPolicy,
    /// Canonical genesis hash the runtime computed.
    pub expected_genesis_hash: &'a GenesisHash,
}

/// Run 130 — v2 bundle-signing-key ratification verifier.
///
/// Performs, in order:
///
///   1. Schema-version check (must be 2).
///   2. Environment / chain / genesis-hash binding.
///   3. Authority-root suite allow-list (ML-DSA-44 only).
///   4. Authority-root lookup in `bundle_signing_authority_roots` only.
///   5. Authority public-key resolution (Run 104 resolution order).
///   6. Target-key suite allow-list (ML-DSA-44 only).
///   7. Target-key length and fingerprint self-consistency.
///   8. `authority_domain_sequence` validity (must be >= 1).
///   9. Lifecycle-action-specific field checks.
///  10. Signature length check.
///  11. ML-DSA-44 signature verification over `sha3_256(v2_preimage)`.
///
/// Returns [`RatifiedBundleSigningKeyV2`] on success; a typed
/// [`RatificationV2Failure`] on every error path. Fail-closed: no
/// `Ok` return is possible unless ALL checks pass.
///
/// Run 130 does **not** wire this verifier into production enforcement
/// surfaces; that is deferred to Run 132.
pub fn verify_bundle_signing_key_ratification_v2(
    inputs: RatificationV2VerifierInputs<'_>,
) -> Result<RatifiedBundleSigningKeyV2, RatificationV2Failure> {
    let v = inputs.ratification;

    // 1. Schema version.
    if v.schema_version != BUNDLE_SIGNING_RATIFICATION_VERSION_V2 {
        return Err(RatificationV2Failure::UnsupportedSchemaVersion {
            got: v.schema_version,
            expected: BUNDLE_SIGNING_RATIFICATION_VERSION_V2,
        });
    }

    // 2a. Environment.
    let expected_env = RatificationEnvironment::from_policy(inputs.expected_environment);
    if v.environment != expected_env {
        return Err(RatificationV2Failure::WrongEnvironment {
            expected: expected_env,
            got: v.environment,
        });
    }

    // 2b. Chain.
    if v.chain_id != inputs.expected_chain_id {
        return Err(RatificationV2Failure::ChainMismatch {
            expected: inputs.expected_chain_id.to_string(),
            got: v.chain_id.clone(),
        });
    }

    // 2c. Genesis hash.
    if &v.genesis_hash != inputs.expected_genesis_hash {
        return Err(RatificationV2Failure::GenesisHashMismatch {
            expected: *inputs.expected_genesis_hash,
            got: v.genesis_hash,
        });
    }

    // 3. Authority-root suite allow-list.
    if v.authority_root_suite_id != GENESIS_AUTHORITY_SUITE_ML_DSA_44 {
        return Err(RatificationV2Failure::AuthoritySuiteUnsupported {
            suite_id: v.authority_root_suite_id,
        });
    }

    // 4. Authority-root lookup (bundle_signing_authority_roots ONLY).
    let bundle_root = find_root(
        &inputs.authority.bundle_signing_authority_roots,
        &v.authority_root_fingerprint,
        v.authority_root_suite_id,
    );
    if bundle_root.is_none() {
        let transport_hit = find_root(
            &inputs.authority.pqc_transport_roots,
            &v.authority_root_fingerprint,
            v.authority_root_suite_id,
        );
        if transport_hit.is_some() {
            return Err(RatificationV2Failure::TransportRootNotAllowed {
                fingerprint: v.authority_root_fingerprint.clone(),
            });
        }
        return Err(RatificationV2Failure::AuthorityRootUnknown {
            fingerprint: v.authority_root_fingerprint.clone(),
        });
    }
    let bundle_root = bundle_root.expect("checked above");

    // 5. Resolve authority public-key bytes (Run 104 resolution order).
    let required_hex_len = ML_DSA_44_PUBLIC_KEY_SIZE * 2;
    let authority_pk: Vec<u8> = if let Some(pk_hex) = bundle_root.public_key_hex.as_deref() {
        if pk_hex.len() != GENESIS_AUTHORITY_ML_DSA_44_PUBLIC_KEY_HEX_LEN {
            return Err(RatificationV2Failure::AuthorityKeyMaterialMalformed {
                fingerprint: bundle_root.key_fingerprint.clone(),
                suite_id: bundle_root.suite_id,
                reason: format!(
                    "public_key_hex length {} != expected {}",
                    pk_hex.len(),
                    GENESIS_AUTHORITY_ML_DSA_44_PUBLIC_KEY_HEX_LEN
                ),
            });
        }
        let pk_bytes = decode_hex(pk_hex).ok_or_else(|| {
            RatificationV2Failure::AuthorityKeyMaterialMalformed {
                fingerprint: bundle_root.key_fingerprint.clone(),
                suite_id: bundle_root.suite_id,
                reason: "public_key_hex is not valid lowercase hex".into(),
            }
        })?;
        if pk_bytes.len() != GENESIS_AUTHORITY_ML_DSA_44_PUBLIC_KEY_BYTES {
            return Err(RatificationV2Failure::AuthorityKeyMaterialMalformed {
                fingerprint: bundle_root.key_fingerprint.clone(),
                suite_id: bundle_root.suite_id,
                reason: format!(
                    "decoded public_key_hex is {} bytes; ML-DSA-44 requires {}",
                    pk_bytes.len(),
                    GENESIS_AUTHORITY_ML_DSA_44_PUBLIC_KEY_BYTES
                ),
            });
        }
        // Enforce fingerprint ↔ public_key_hex binding.
        if bundle_root.key_fingerprint.len() == GENESIS_AUTHORITY_KEY_FINGERPRINT_HEX_LEN {
            let derived = authority_public_key_fingerprint(&pk_bytes);
            if derived != bundle_root.key_fingerprint {
                return Err(RatificationV2Failure::AuthorityKeyMaterialMalformed {
                    fingerprint: bundle_root.key_fingerprint.clone(),
                    suite_id: bundle_root.suite_id,
                    reason: format!(
                        "public_key_hex sha3_256={derived} does not match declared key_fingerprint={}",
                        bundle_root.key_fingerprint
                    ),
                });
            }
        }
        // Defense-in-depth: check that the authority fingerprint declared in
        // the ratification itself matches the derived fingerprint, for the
        // canonical short-fingerprint case.
        if v.authority_root_fingerprint.len() == GENESIS_AUTHORITY_KEY_FINGERPRINT_HEX_LEN {
            let derived = authority_public_key_fingerprint(&pk_bytes);
            if derived != v.authority_root_fingerprint {
                return Err(RatificationV2Failure::AuthorityFingerprintMismatch {
                    declared: v.authority_root_fingerprint.clone(),
                    derived,
                });
            }
        }
        pk_bytes
    } else {
        // Legacy fallback: key_fingerprint may carry the full PK hex.
        let fp_hex = &bundle_root.key_fingerprint;
        if fp_hex.len() != required_hex_len {
            return Err(RatificationV2Failure::AuthorityKeyMaterialUnavailable {
                fingerprint: bundle_root.key_fingerprint.clone(),
                suite_id: bundle_root.suite_id,
                got_hex_len: fp_hex.len(),
                required_hex_len,
            });
        }
        let pk = decode_hex(fp_hex).ok_or_else(|| {
            RatificationV2Failure::AuthorityKeyMaterialUnavailable {
                fingerprint: bundle_root.key_fingerprint.clone(),
                suite_id: bundle_root.suite_id,
                got_hex_len: fp_hex.len(),
                required_hex_len,
            }
        })?;
        if pk.len() != ML_DSA_44_PUBLIC_KEY_SIZE {
            return Err(RatificationV2Failure::AuthorityKeyMaterialUnavailable {
                fingerprint: bundle_root.key_fingerprint.clone(),
                suite_id: bundle_root.suite_id,
                got_hex_len: fp_hex.len(),
                required_hex_len,
            });
        }
        pk
    };

    // 6. Target-key suite allow-list.
    if v.target_bundle_signing_key_suite_id != GENESIS_AUTHORITY_SUITE_ML_DSA_44 {
        return Err(RatificationV2Failure::TargetKeySuiteUnsupported {
            suite_id: v.target_bundle_signing_key_suite_id,
        });
    }

    // 7a. Target-key length.
    if v.target_bundle_signing_public_key.len() != ML_DSA_44_PUBLIC_KEY_SIZE {
        return Err(RatificationV2Failure::MalformedTargetPublicKey {
            suite_id: v.target_bundle_signing_key_suite_id,
            got_len: v.target_bundle_signing_public_key.len(),
            expected_len: ML_DSA_44_PUBLIC_KEY_SIZE,
        });
    }

    // 7b. Target-key fingerprint self-consistency.
    let recomputed_fp = sha3_256_hex(&v.target_bundle_signing_public_key);
    if v.target_bundle_signing_key_fingerprint != recomputed_fp {
        return Err(RatificationV2Failure::TargetKeyFingerprintMismatch {
            expected: recomputed_fp,
            got: v.target_bundle_signing_key_fingerprint.clone(),
        });
    }

    // 8. authority_domain_sequence must be >= 1.
    if v.authority_domain_sequence == 0 {
        return Err(RatificationV2Failure::InvalidAuthorityDomainSequence {
            got: v.authority_domain_sequence,
        });
    }

    // 9. Lifecycle-action-specific field checks.
    match v.key_lifecycle_action {
        BundleSigningRatificationV2Action::Ratify => {
            // Ratify must NOT carry rotation-only fields.
            if v.previous_key_fingerprint.is_some() || v.previous_ratification_digest.is_some() {
                return Err(RatificationV2Failure::UnexpectedRotateFieldsForRatify);
            }
        }
        BundleSigningRatificationV2Action::Rotate => {
            // Rotate MUST have both previous_key_fingerprint and
            // previous_ratification_digest.
            if v.previous_key_fingerprint.is_none() {
                return Err(RatificationV2Failure::MissingPreviousKeyForRotate);
            }
            if v.previous_ratification_digest.is_none() {
                return Err(RatificationV2Failure::MissingPreviousDigestForRotate);
            }
            // Validate the digest hex format.
            let digest_hex = v
                .previous_ratification_digest
                .as_deref()
                .expect("checked above");
            if digest_hex.len() != 64 {
                return Err(RatificationV2Failure::MalformedPreviousDigest {
                    reason: format!(
                        "previous_ratification_digest must be 64 hex chars (32 bytes); got {} chars",
                        digest_hex.len()
                    ),
                });
            }
            if decode_hex(digest_hex).is_none() {
                return Err(RatificationV2Failure::MalformedPreviousDigest {
                    reason: "previous_ratification_digest is not valid lowercase hex".into(),
                });
            }
        }
        BundleSigningRatificationV2Action::Revoke => {
            // Revoke MUST have at least one of revocation_reason or
            // capabilities_scope.
            if v.revocation_reason.is_none() && v.capabilities_scope.is_none() {
                return Err(RatificationV2Failure::MissingRevocationFieldsForRevoke);
            }
        }
    }

    // 10. Signature length.
    if v.signature.len() != ML_DSA_44_SIGNATURE_SIZE {
        return Err(RatificationV2Failure::MalformedSignature {
            suite_id: v.authority_root_suite_id,
            got_len: v.signature.len(),
            expected_len: ML_DSA_44_SIGNATURE_SIZE,
        });
    }

    // 11. ML-DSA-44 signature verification using the existing production adapter.
    let digest = canonical_ratification_v2_digest(v);
    let suite = MlDsa44SignatureSuite::new(GENESIS_AUTHORITY_SUITE_ML_DSA_44);
    match suite.verify(&authority_pk, &digest, &v.signature) {
        Ok(()) => Ok(RatifiedBundleSigningKeyV2 {
            public_key: v.target_bundle_signing_public_key.clone(),
            fingerprint: v.target_bundle_signing_key_fingerprint.clone(),
            suite_id: v.target_bundle_signing_key_suite_id,
            authority_root_fingerprint: v.authority_root_fingerprint.clone(),
            authority_policy_version: v.authority_policy_version,
            authority_domain_sequence: v.authority_domain_sequence,
            key_lifecycle_action: v.key_lifecycle_action,
        }),
        Err(_) => Err(RatificationV2Failure::SignatureInvalid),
    }
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

/// Test-only helper to mint a fully-signed [`BundleSigningRatificationV2`].
///
/// Only compiled under `cfg(any(test, feature = "test-helpers"))`.
#[cfg(any(test, feature = "test-helpers"))]
pub mod v2_test_helpers {
    use super::*;
    use qbind_crypto::ml_dsa_44_sign_digest;

    /// Build and sign a v2 ratification object with the given lifecycle action.
    ///
    /// `authority_pk_hex` is the lowercase hex of the authority public key,
    /// used as `authority_root_fingerprint` in the object and as the
    /// genesis-bound root's `key_fingerprint`.
    #[allow(clippy::too_many_arguments)]
    pub fn build_signed_ratification_v2(
        chain_id: &str,
        environment: RatificationEnvironment,
        genesis_hash: GenesisHash,
        authority_policy_version: u32,
        authority_pk_hex: &str,
        authority_sk: &[u8],
        target_bsk_pk: &[u8],
        authority_domain_sequence: u64,
        action: BundleSigningRatificationV2Action,
        previous_key_fingerprint: Option<String>,
        previous_ratification_digest: Option<String>,
        valid_from_epoch: Option<u64>,
        valid_until_epoch: Option<u64>,
        revocation_reason: Option<String>,
        capabilities_scope: Option<String>,
    ) -> BundleSigningRatificationV2 {
        let fp = pqc_public_key_fingerprint(target_bsk_pk);
        let mut v = BundleSigningRatificationV2 {
            schema_version: BUNDLE_SIGNING_RATIFICATION_VERSION_V2,
            environment,
            chain_id: chain_id.to_string(),
            genesis_hash,
            authority_policy_version,
            authority_root_fingerprint: authority_pk_hex.to_string(),
            authority_root_suite_id: GENESIS_AUTHORITY_SUITE_ML_DSA_44,
            target_bundle_signing_key_fingerprint: fp,
            target_bundle_signing_key_suite_id: GENESIS_AUTHORITY_SUITE_ML_DSA_44,
            target_bundle_signing_public_key: target_bsk_pk.to_vec(),
            authority_domain_sequence,
            key_lifecycle_action: action,
            previous_key_fingerprint,
            previous_ratification_digest,
            valid_from_epoch,
            valid_until_epoch,
            revocation_reason,
            capabilities_scope,
            signature: Vec::new(),
        };
        let digest = canonical_ratification_v2_digest(&v);
        let sig = ml_dsa_44_sign_digest(authority_sk, &digest)
            .expect("ml_dsa_44_sign_digest in v2 test helper must succeed");
        v.signature = sig;
        v
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
            vec![GenesisAllocation::new(
                format!("0x{}", "11".repeat(32)),
                100,
            )],
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
            vec![GenesisAllocation::new(
                format!("0x{}", "11".repeat(32)),
                100,
            )],
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
        let pk_mut = cfg
            .authority
            .as_mut()
            .unwrap()
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
            matches!(
                err,
                RatificationFailure::AuthorityKeyMaterialMalformed { .. }
            ),
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
        cfg.authority
            .as_mut()
            .unwrap()
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
            matches!(
                err,
                RatificationFailure::AuthorityKeyMaterialMalformed { .. }
            ),
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
        cfg.authority
            .as_mut()
            .unwrap()
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

    // -----------------------------------------------------------------
    // Run 105 — enforcement-layer tests
    // -----------------------------------------------------------------

    fn mk_enforcement_inputs<'a>(
        ratification: Option<&'a BundleSigningRatification>,
        authority: &'a GenesisAuthorityConfig,
        chain_id: &'a str,
        env: NetworkEnvironmentPolicy,
        gh: &'a GenesisHash,
        bundle_signing_pk: &'a [u8],
        policy: RatificationEnforcementPolicy,
    ) -> RatificationEnforcementInputs<'a> {
        RatificationEnforcementInputs {
            ratification,
            authority,
            expected_chain_id: chain_id,
            expected_environment: env,
            expected_genesis_hash: gh,
            candidate_bundle_signing_public_key: bundle_signing_pk,
            policy,
        }
    }

    #[test]
    fn run_105_strict_mainnet_accepts_valid_ratification() {
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
        let outcome = enforce_bundle_signing_key_ratification(mk_enforcement_inputs(
            Some(&r),
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
            &bsk_pk,
            RatificationEnforcementPolicy::Strict,
        ))
        .expect("valid ratification must succeed under strict mainnet");
        match outcome {
            RatificationEnforcementOutcome::Ratified(rk) => {
                assert_eq!(rk.public_key, bsk_pk);
                assert_eq!(rk.signature_suite_id, GENESIS_AUTHORITY_SUITE_ML_DSA_44);
            }
            other => panic!("expected Ratified, got {:?}", other),
        }
    }

    #[test]
    fn run_105_strict_mainnet_rejects_missing_ratification() {
        let (auth_pk, _auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let auth = cfg.authority.as_ref().unwrap();
        let err = enforce_bundle_signing_key_ratification(mk_enforcement_inputs(
            None,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
            &bsk_pk,
            RatificationEnforcementPolicy::Strict,
        ))
        .unwrap_err();
        match err {
            RatificationEnforcementFailure::Missing {
                environment,
                bundle_signing_public_key_fingerprint,
            } => {
                assert_eq!(environment, RatificationEnvironment::Mainnet);
                assert_eq!(bundle_signing_public_key_fingerprint, sha3_256_hex(&bsk_pk));
            }
            other => panic!("expected Missing, got {:?}", other),
        }
    }

    #[test]
    fn run_105_strict_testnet_rejects_missing_ratification() {
        let (auth_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-testnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Testnet);
        let auth = cfg.authority.as_ref().unwrap();
        let err = enforce_bundle_signing_key_ratification(mk_enforcement_inputs(
            None,
            auth,
            "qbind-testnet-v0",
            NetworkEnvironmentPolicy::Testnet,
            &gh,
            &bsk_pk,
            RatificationEnforcementPolicy::Strict,
        ))
        .unwrap_err();
        assert!(matches!(
            err,
            RatificationEnforcementFailure::Missing { .. }
        ));
    }

    #[test]
    fn run_105_mainnet_refuses_legacy_unratified_policy() {
        let (auth_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let auth = cfg.authority.as_ref().unwrap();
        let err = enforce_bundle_signing_key_ratification(mk_enforcement_inputs(
            None,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
            &bsk_pk,
            RatificationEnforcementPolicy::AllowLegacyUnratified,
        ))
        .unwrap_err();
        assert!(matches!(
            err,
            RatificationEnforcementFailure::LegacyUnratifiedRefusedOnMainnet
        ));
    }

    #[test]
    fn run_105_devnet_legacy_unratified_returns_explicit_verdict() {
        let (auth_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-devnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Devnet);
        let auth = cfg.authority.as_ref().unwrap();
        let outcome = enforce_bundle_signing_key_ratification(mk_enforcement_inputs(
            None,
            auth,
            "qbind-devnet-v0",
            NetworkEnvironmentPolicy::Devnet,
            &gh,
            &bsk_pk,
            RatificationEnforcementPolicy::AllowLegacyUnratified,
        ))
        .expect("DevNet legacy-unratified must produce an explicit verdict, not a failure");
        match outcome {
            RatificationEnforcementOutcome::LegacyUnratifiedAccepted {
                bundle_signing_public_key_fingerprint,
            } => {
                assert_eq!(bundle_signing_public_key_fingerprint, sha3_256_hex(&bsk_pk));
            }
            other => panic!("expected LegacyUnratifiedAccepted, got {:?}", other),
        }
    }

    #[test]
    fn run_105_rejects_ratification_for_different_key() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk_a, _) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk_b, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        // Ratify key A
        let r = test_helpers::build_signed_ratification(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk_a,
        );
        let auth = cfg.authority.as_ref().unwrap();
        // But supply candidate key B
        let err = enforce_bundle_signing_key_ratification(mk_enforcement_inputs(
            Some(&r),
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
            &bsk_pk_b,
            RatificationEnforcementPolicy::Strict,
        ))
        .unwrap_err();
        match err {
            RatificationEnforcementFailure::RatifiesDifferentKey {
                ratified_fingerprint,
                candidate_fingerprint,
            } => {
                assert_eq!(ratified_fingerprint, sha3_256_hex(&bsk_pk_a));
                assert_eq!(candidate_fingerprint, sha3_256_hex(&bsk_pk_b));
            }
            other => panic!("expected RatifiesDifferentKey, got {:?}", other),
        }
    }

    #[test]
    fn run_105_propagates_verifier_failure_on_wrong_chain() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        // Ratification bound to a *different* chain
        let r = test_helpers::build_signed_ratification(
            "some-other-chain-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
        );
        let auth = cfg.authority.as_ref().unwrap();
        let err = enforce_bundle_signing_key_ratification(mk_enforcement_inputs(
            Some(&r),
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
            &bsk_pk,
            RatificationEnforcementPolicy::Strict,
        ))
        .unwrap_err();
        assert!(matches!(
            err,
            RatificationEnforcementFailure::Verifier(RatificationFailure::ChainMismatch { .. })
        ));
    }

    #[test]
    fn run_105_strict_refuses_when_authority_block_has_no_bundle_signing_roots() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let mut cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        // Strip bundle-signing roots after construction.
        cfg.authority
            .as_mut()
            .unwrap()
            .bundle_signing_authority_roots
            .clear();
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
        let err = enforce_bundle_signing_key_ratification(mk_enforcement_inputs(
            Some(&r),
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
            &bsk_pk,
            RatificationEnforcementPolicy::Strict,
        ))
        .unwrap_err();
        assert!(matches!(
            err,
            RatificationEnforcementFailure::NoBundleSigningAuthorityConfigured { .. }
        ));
    }

    #[test]
    fn run_105_transport_root_cannot_ratify_via_enforcer() {
        // Construct a genesis with only a transport root (no bundle-
        // signing root). The enforcer's strict-no-bundle-signing-roots
        // gate fires first, but if a bundle-signing root is also
        // present and the operator points the ratification at the
        // transport root, the verifier rejects with TransportRootNotAllowed.
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (transport_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let mut cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        // Add a transport root and have the ratification point at it.
        cfg.authority
            .as_mut()
            .unwrap()
            .pqc_transport_roots
            .push(GenesisAuthorityRoot::new(
                GENESIS_AUTHORITY_SUITE_ML_DSA_44,
                &full_pk_hex(&transport_pk),
                "transport-1",
            ));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let mut r = test_helpers::build_signed_ratification(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
        );
        // Re-target the ratification at the transport root fingerprint
        // (signature is now invalid for that key, but the verifier
        // returns TransportRootNotAllowed before reaching signature
        // verification because the lookup happens first).
        r.authority_root_fingerprint = full_pk_hex(&transport_pk);
        let auth = cfg.authority.as_ref().unwrap();
        let err = enforce_bundle_signing_key_ratification(mk_enforcement_inputs(
            Some(&r),
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
            &bsk_pk,
            RatificationEnforcementPolicy::Strict,
        ))
        .unwrap_err();
        match err {
            RatificationEnforcementFailure::Verifier(
                RatificationFailure::TransportRootNotAllowed { .. },
            )
            | RatificationEnforcementFailure::Verifier(
                RatificationFailure::UnknownAuthorityRoot { .. },
            ) => {}
            other => panic!(
                "expected TransportRootNotAllowed or UnknownAuthorityRoot, got {:?}",
                other
            ),
        }
    }

    // =======================================================================
    // Run 130 — Ratification v2 tests
    // =======================================================================

    use super::{
        canonical_ratification_v2_digest, ratification_v2_signing_preimage,
        v2_test_helpers::build_signed_ratification_v2, verify_bundle_signing_key_ratification_v2,
        BundleSigningRatificationV2, BundleSigningRatificationV2Action, RatificationV2Failure,
        RatificationV2VerifierInputs, BUNDLE_SIGNING_RATIFICATION_DOMAIN_V1,
        BUNDLE_SIGNING_RATIFICATION_DOMAIN_V2,
    };

    // -----------------------------------------------------------------------
    // v2 helpers
    // -----------------------------------------------------------------------

    fn mk_v2_inputs<'a>(
        v: &'a BundleSigningRatificationV2,
        authority: &'a GenesisAuthorityConfig,
        chain_id: &'a str,
        env: NetworkEnvironmentPolicy,
        gh: &'a GenesisHash,
    ) -> RatificationV2VerifierInputs<'a> {
        RatificationV2VerifierInputs {
            ratification: v,
            authority,
            expected_chain_id: chain_id,
            expected_environment: env,
            expected_genesis_hash: gh,
        }
    }

    fn build_v2_ratify(
        chain_id: &str,
        env: RatificationEnvironment,
        genesis_hash: GenesisHash,
        authority_pk_hex: &str,
        authority_sk: &[u8],
        target_bsk_pk: &[u8],
        seq: u64,
    ) -> BundleSigningRatificationV2 {
        build_signed_ratification_v2(
            chain_id,
            env,
            genesis_hash,
            1,
            authority_pk_hex,
            authority_sk,
            target_bsk_pk,
            seq,
            BundleSigningRatificationV2Action::Ratify,
            None,
            None,
            None,
            None,
            None,
            None,
        )
    }

    // -----------------------------------------------------------------------
    // A. Canonical preimage / digest tests
    // -----------------------------------------------------------------------

    #[test]
    fn v2_preimage_starts_with_v2_domain_tag() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let v = build_v2_ratify(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
            1,
        );
        let p = ratification_v2_signing_preimage(&v);
        assert!(p.starts_with(BUNDLE_SIGNING_RATIFICATION_DOMAIN_V2));
        assert!(!p.starts_with(BUNDLE_SIGNING_RATIFICATION_DOMAIN_V1));
    }

    #[test]
    fn v2_preimage_is_deterministic() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let v = build_v2_ratify(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
            1,
        );
        let p1 = ratification_v2_signing_preimage(&v);
        let p2 = ratification_v2_signing_preimage(&v);
        assert_eq!(p1, p2);
        let d1 = canonical_ratification_v2_digest(&v);
        let d2 = canonical_ratification_v2_digest(&v);
        assert_eq!(d1, d2);
    }

    #[test]
    fn v2_and_v1_domain_tags_are_distinct() {
        assert_ne!(
            BUNDLE_SIGNING_RATIFICATION_DOMAIN_V1,
            BUNDLE_SIGNING_RATIFICATION_DOMAIN_V2
        );
    }

    #[test]
    fn v2_preimage_changes_with_each_security_field() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let base = build_v2_ratify(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
            1,
        );
        let base_p = ratification_v2_signing_preimage(&base);

        // environment
        let mut m = base.clone();
        m.environment = RatificationEnvironment::Testnet;
        assert_ne!(
            ratification_v2_signing_preimage(&m),
            base_p,
            "environment must change digest"
        );

        // chain_id
        let mut m = base.clone();
        m.chain_id = "qbind-mainnet-vX".into();
        assert_ne!(
            ratification_v2_signing_preimage(&m),
            base_p,
            "chain_id must change digest"
        );

        // genesis_hash
        let mut m = base.clone();
        m.genesis_hash[0] ^= 0xFF;
        assert_ne!(
            ratification_v2_signing_preimage(&m),
            base_p,
            "genesis_hash must change digest"
        );

        // authority_root_fingerprint
        let mut m = base.clone();
        m.authority_root_fingerprint.push('0');
        assert_ne!(
            ratification_v2_signing_preimage(&m),
            base_p,
            "authority fp must change digest"
        );

        // authority_root_suite_id
        let mut m = base.clone();
        m.authority_root_suite_id = 7;
        assert_ne!(
            ratification_v2_signing_preimage(&m),
            base_p,
            "authority suite must change digest"
        );

        // target key fingerprint
        let mut m = base.clone();
        m.target_bundle_signing_key_fingerprint = "00".repeat(32);
        assert_ne!(
            ratification_v2_signing_preimage(&m),
            base_p,
            "target fp must change digest"
        );

        // target key suite_id
        let mut m = base.clone();
        m.target_bundle_signing_key_suite_id = 7;
        assert_ne!(
            ratification_v2_signing_preimage(&m),
            base_p,
            "target suite must change digest"
        );

        // target key bytes
        let mut m = base.clone();
        m.target_bundle_signing_public_key[0] ^= 0xFF;
        assert_ne!(
            ratification_v2_signing_preimage(&m),
            base_p,
            "target key must change digest"
        );

        // authority_domain_sequence
        let mut m = base.clone();
        m.authority_domain_sequence = 99;
        assert_ne!(
            ratification_v2_signing_preimage(&m),
            base_p,
            "sequence must change digest"
        );

        // lifecycle action
        let mut m = base.clone();
        m.key_lifecycle_action = BundleSigningRatificationV2Action::Revoke;
        assert_ne!(
            ratification_v2_signing_preimage(&m),
            base_p,
            "lifecycle action must change digest"
        );

        // authority_policy_version
        let mut m = base.clone();
        m.authority_policy_version = 99;
        assert_ne!(
            ratification_v2_signing_preimage(&m),
            base_p,
            "authority_policy_version must change digest"
        );
    }

    #[test]
    fn v2_preimage_rotate_fields_change_digest() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let (prev_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let prev_digest_hex = "aa".repeat(32);
        let base = build_signed_ratification_v2(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            1,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
            2,
            BundleSigningRatificationV2Action::Rotate,
            Some(pqc_public_key_fingerprint(&prev_pk)),
            Some(prev_digest_hex.clone()),
            None,
            None,
            None,
            None,
        );
        let base_p = ratification_v2_signing_preimage(&base);

        // changing previous_key_fingerprint
        let mut m = base.clone();
        m.previous_key_fingerprint = Some("bb".repeat(32));
        assert_ne!(ratification_v2_signing_preimage(&m), base_p);

        // changing previous_ratification_digest
        let mut m = base.clone();
        m.previous_ratification_digest = Some("cc".repeat(32));
        assert_ne!(ratification_v2_signing_preimage(&m), base_p);

        // removing previous_key_fingerprint
        let mut m = base.clone();
        m.previous_key_fingerprint = None;
        assert_ne!(ratification_v2_signing_preimage(&m), base_p);
    }

    #[test]
    fn v2_preimage_revoke_reason_changes_digest() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let base = build_signed_ratification_v2(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            1,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
            3,
            BundleSigningRatificationV2Action::Revoke,
            None,
            None,
            None,
            None,
            Some("compromised".to_string()),
            Some("all".to_string()),
        );
        let base_p = ratification_v2_signing_preimage(&base);

        // changing revocation_reason
        let mut m = base.clone();
        m.revocation_reason = Some("expired".to_string());
        assert_ne!(ratification_v2_signing_preimage(&m), base_p);

        // changing capabilities_scope
        let mut m = base.clone();
        m.capabilities_scope = Some("signing-only".to_string());
        assert_ne!(ratification_v2_signing_preimage(&m), base_p);
    }

    #[test]
    fn v2_same_object_produces_same_digest() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let v = build_v2_ratify(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
            1,
        );
        assert_eq!(
            canonical_ratification_v2_digest(&v),
            canonical_ratification_v2_digest(&v),
        );
    }

    // -----------------------------------------------------------------------
    // B. Verifier success tests
    // -----------------------------------------------------------------------

    #[test]
    fn v2_ratify_verifies_successfully() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let v = build_v2_ratify(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
            1,
        );
        let auth = cfg.authority.as_ref().unwrap();
        let ok = verify_bundle_signing_key_ratification_v2(mk_v2_inputs(
            &v,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .expect("valid v2 ratify must verify");
        assert_eq!(ok.public_key, bsk_pk);
        assert_eq!(ok.authority_domain_sequence, 1);
        assert_eq!(
            ok.key_lifecycle_action,
            BundleSigningRatificationV2Action::Ratify
        );
        assert_eq!(ok.suite_id, GENESIS_AUTHORITY_SUITE_ML_DSA_44);
    }

    #[test]
    fn v2_rotate_verifies_successfully_with_previous_fields() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let (prev_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let prev_digest = "ab".repeat(32);
        let v = build_signed_ratification_v2(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            1,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
            2,
            BundleSigningRatificationV2Action::Rotate,
            Some(pqc_public_key_fingerprint(&prev_pk)),
            Some(prev_digest),
            None,
            None,
            None,
            None,
        );
        let auth = cfg.authority.as_ref().unwrap();
        let ok = verify_bundle_signing_key_ratification_v2(mk_v2_inputs(
            &v,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .expect("valid v2 rotate must verify");
        assert_eq!(
            ok.key_lifecycle_action,
            BundleSigningRatificationV2Action::Rotate
        );
        assert_eq!(ok.authority_domain_sequence, 2);
    }

    #[test]
    fn v2_revoke_verifies_successfully_with_revoke_fields() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let v = build_signed_ratification_v2(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            1,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
            3,
            BundleSigningRatificationV2Action::Revoke,
            None,
            None,
            None,
            None,
            Some("compromised".to_string()),
            Some("all".to_string()),
        );
        let auth = cfg.authority.as_ref().unwrap();
        let ok = verify_bundle_signing_key_ratification_v2(mk_v2_inputs(
            &v,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .expect("valid v2 revoke must verify");
        assert_eq!(
            ok.key_lifecycle_action,
            BundleSigningRatificationV2Action::Revoke
        );
    }

    #[test]
    fn v2_authority_lookup_uses_bundle_signing_roots_only() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (transport_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        // Genesis: bundle-signing set = auth_pk, transport set = transport_pk.
        let mut cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        cfg.authority.as_mut().unwrap().pqc_transport_roots = vec![GenesisAuthorityRoot::new(
            GENESIS_AUTHORITY_SUITE_ML_DSA_44,
            full_pk_hex(&transport_pk),
            "transport-1",
        )];
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        // Ratification signed by auth_pk (in bundle-signing set) must succeed.
        let v = build_v2_ratify(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
            1,
        );
        let auth = cfg.authority.as_ref().unwrap();
        verify_bundle_signing_key_ratification_v2(mk_v2_inputs(
            &v,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .expect("bundle-signing root must succeed in v2");
    }

    // -----------------------------------------------------------------------
    // C. Verifier failure tests
    // -----------------------------------------------------------------------

    #[test]
    fn v2_wrong_schema_version_rejected() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let mut v = build_v2_ratify(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
            1,
        );
        v.schema_version = 1;
        let auth = cfg.authority.as_ref().unwrap();
        let err = verify_bundle_signing_key_ratification_v2(mk_v2_inputs(
            &v,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .unwrap_err();
        assert!(
            matches!(
                err,
                RatificationV2Failure::UnsupportedSchemaVersion { got: 1, .. }
            ),
            "{err}"
        );
    }

    #[test]
    fn v2_wrong_environment_rejected() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let mut v = build_v2_ratify(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
            1,
        );
        v.environment = RatificationEnvironment::Testnet;
        let auth = cfg.authority.as_ref().unwrap();
        let err = verify_bundle_signing_key_ratification_v2(mk_v2_inputs(
            &v,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .unwrap_err();
        assert!(
            matches!(err, RatificationV2Failure::WrongEnvironment { .. }),
            "{err}"
        );
    }

    #[test]
    fn v2_wrong_chain_rejected() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let mut v = build_v2_ratify(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
            1,
        );
        v.chain_id = "qbind-testnet-beta".into();
        let auth = cfg.authority.as_ref().unwrap();
        let err = verify_bundle_signing_key_ratification_v2(mk_v2_inputs(
            &v,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .unwrap_err();
        assert!(
            matches!(err, RatificationV2Failure::ChainMismatch { .. }),
            "{err}"
        );
    }

    #[test]
    fn v2_wrong_genesis_rejected() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let v = build_v2_ratify(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
            1,
        );
        let mut wrong_gh = gh;
        wrong_gh[0] ^= 0xFF;
        let auth = cfg.authority.as_ref().unwrap();
        let err = verify_bundle_signing_key_ratification_v2(mk_v2_inputs(
            &v,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &wrong_gh,
        ))
        .unwrap_err();
        assert!(
            matches!(err, RatificationV2Failure::GenesisHashMismatch { .. }),
            "{err}"
        );
    }

    #[test]
    fn v2_unknown_authority_root_rejected() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (other_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        // Genesis trusts other_pk; ratification claims auth_pk.
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&other_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let v = build_v2_ratify(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
            1,
        );
        let auth = cfg.authority.as_ref().unwrap();
        let err = verify_bundle_signing_key_ratification_v2(mk_v2_inputs(
            &v,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .unwrap_err();
        assert!(
            matches!(err, RatificationV2Failure::AuthorityRootUnknown { .. }),
            "{err}"
        );
    }

    #[test]
    fn v2_transport_root_rejected() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (other_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let mut cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&other_pk));
        cfg.authority.as_mut().unwrap().pqc_transport_roots = vec![GenesisAuthorityRoot::new(
            GENESIS_AUTHORITY_SUITE_ML_DSA_44,
            full_pk_hex(&auth_pk),
            "transport-1",
        )];
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let v = build_v2_ratify(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
            1,
        );
        let auth = cfg.authority.as_ref().unwrap();
        let err = verify_bundle_signing_key_ratification_v2(mk_v2_inputs(
            &v,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .unwrap_err();
        assert!(
            matches!(err, RatificationV2Failure::TransportRootNotAllowed { .. }),
            "{err}"
        );
    }

    #[test]
    fn v2_malformed_authority_public_key_rejected() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let mut cfg = mk_genesis_run_104_clean("qbind-mainnet-v0", &auth_pk);
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let fp_hex = pqc_public_key_fingerprint(&auth_pk);
        let v = build_v2_ratify(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &fp_hex,
            &auth_sk,
            &bsk_pk,
            1,
        );
        // Corrupt the genesis-bound public_key_hex.
        let pk_mut = cfg
            .authority
            .as_mut()
            .unwrap()
            .bundle_signing_authority_roots[0]
            .public_key_hex
            .as_mut()
            .unwrap();
        pk_mut.truncate(pk_mut.len() - 2);
        let auth = cfg.authority.as_ref().unwrap();
        let err = verify_bundle_signing_key_ratification_v2(mk_v2_inputs(
            &v,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .unwrap_err();
        assert!(
            matches!(
                err,
                RatificationV2Failure::AuthorityKeyMaterialMalformed { .. }
            ),
            "{err}"
        );
    }

    #[test]
    fn v2_target_key_fingerprint_mismatch_rejected() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let mut v = build_v2_ratify(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
            1,
        );
        v.target_bundle_signing_key_fingerprint = "00".repeat(32);
        let auth = cfg.authority.as_ref().unwrap();
        let err = verify_bundle_signing_key_ratification_v2(mk_v2_inputs(
            &v,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .unwrap_err();
        assert!(
            matches!(
                err,
                RatificationV2Failure::TargetKeyFingerprintMismatch { .. }
            ),
            "{err}"
        );
    }

    #[test]
    fn v2_bad_signature_rejected() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let mut v = build_v2_ratify(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
            1,
        );
        v.signature[0] ^= 0xFF;
        let auth = cfg.authority.as_ref().unwrap();
        let err = verify_bundle_signing_key_ratification_v2(mk_v2_inputs(
            &v,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .unwrap_err();
        assert!(
            matches!(err, RatificationV2Failure::SignatureInvalid),
            "{err}"
        );
    }

    #[test]
    fn v2_missing_authority_domain_sequence_rejected() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let mut v = build_v2_ratify(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
            1,
        );
        // sequence 0 is invalid (must be >= 1).
        v.authority_domain_sequence = 0;
        // Re-sign so the signature is valid for this (invalid) object.
        let digest = canonical_ratification_v2_digest(&v);
        v.signature = qbind_crypto::ml_dsa_44_sign_digest(&auth_sk, &digest).unwrap();
        let auth = cfg.authority.as_ref().unwrap();
        let err = verify_bundle_signing_key_ratification_v2(mk_v2_inputs(
            &v,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .unwrap_err();
        assert!(
            matches!(
                err,
                RatificationV2Failure::InvalidAuthorityDomainSequence { got: 0 }
            ),
            "{err}"
        );
    }

    #[test]
    fn v2_rotate_missing_previous_key_rejected() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let v = build_signed_ratification_v2(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            1,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
            2,
            BundleSigningRatificationV2Action::Rotate,
            None, // ← missing previous_key_fingerprint
            Some("ab".repeat(32)),
            None,
            None,
            None,
            None,
        );
        let auth = cfg.authority.as_ref().unwrap();
        let err = verify_bundle_signing_key_ratification_v2(mk_v2_inputs(
            &v,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .unwrap_err();
        assert!(
            matches!(err, RatificationV2Failure::MissingPreviousKeyForRotate),
            "{err}"
        );
    }

    #[test]
    fn v2_rotate_missing_previous_digest_rejected() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let (prev_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let v = build_signed_ratification_v2(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            1,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
            2,
            BundleSigningRatificationV2Action::Rotate,
            Some(pqc_public_key_fingerprint(&prev_pk)),
            None, // ← missing previous_ratification_digest
            None,
            None,
            None,
            None,
        );
        let auth = cfg.authority.as_ref().unwrap();
        let err = verify_bundle_signing_key_ratification_v2(mk_v2_inputs(
            &v,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .unwrap_err();
        assert!(
            matches!(err, RatificationV2Failure::MissingPreviousDigestForRotate),
            "{err}"
        );
    }

    #[test]
    fn v2_ratify_with_unexpected_rotate_fields_rejected() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let v = build_signed_ratification_v2(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            1,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
            1,
            BundleSigningRatificationV2Action::Ratify,
            Some("ff".repeat(32)), // ← unexpected rotation field
            None,
            None,
            None,
            None,
            None,
        );
        let auth = cfg.authority.as_ref().unwrap();
        let err = verify_bundle_signing_key_ratification_v2(mk_v2_inputs(
            &v,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .unwrap_err();
        assert!(
            matches!(err, RatificationV2Failure::UnexpectedRotateFieldsForRatify),
            "{err}"
        );
    }

    #[test]
    fn v2_revoke_missing_revoke_fields_rejected() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let v = build_signed_ratification_v2(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            1,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
            3,
            BundleSigningRatificationV2Action::Revoke,
            None,
            None,
            None,
            None,
            None, // ← missing revocation_reason
            None, // ← missing capabilities_scope
        );
        let auth = cfg.authority.as_ref().unwrap();
        let err = verify_bundle_signing_key_ratification_v2(mk_v2_inputs(
            &v,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .unwrap_err();
        assert!(
            matches!(err, RatificationV2Failure::MissingRevocationFieldsForRevoke),
            "{err}"
        );
    }

    #[test]
    fn v2_malformed_signature_rejected() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let mut v = build_v2_ratify(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
            1,
        );
        v.signature.truncate(50);
        let auth = cfg.authority.as_ref().unwrap();
        let err = verify_bundle_signing_key_ratification_v2(mk_v2_inputs(
            &v,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .unwrap_err();
        assert!(
            matches!(err, RatificationV2Failure::MalformedSignature { .. }),
            "{err}"
        );
    }

    // -----------------------------------------------------------------------
    // D. v1 regression — existing verifier unaffected by Run 130 additions
    // -----------------------------------------------------------------------

    #[test]
    fn v1_verifier_still_rejects_v2_schema_version() {
        // If someone sets version=2 on a v1 struct, the v1 verifier must
        // refuse it with UnsupportedVersion.
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
        assert!(
            matches!(err, RatificationFailure::UnsupportedVersion { got: 2, .. }),
            "{err}"
        );
    }

    #[test]
    fn v2_verifier_rejects_v1_schema_version() {
        // A BundleSigningRatificationV2 with schema_version=1 is rejected.
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let mut v = build_v2_ratify(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
            1,
        );
        v.schema_version = 1;
        let auth = cfg.authority.as_ref().unwrap();
        let err = verify_bundle_signing_key_ratification_v2(mk_v2_inputs(
            &v,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .unwrap_err();
        assert!(
            matches!(
                err,
                RatificationV2Failure::UnsupportedSchemaVersion { got: 1, .. }
            ),
            "{err}"
        );
    }

    #[test]
    fn v2_json_round_trip_preserves_object_and_still_verifies() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let v = build_v2_ratify(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
            1,
        );
        let s = serde_json::to_string(&v).expect("v2 ser");
        let v2: BundleSigningRatificationV2 = serde_json::from_str(&s).expect("v2 de");
        assert_eq!(v, v2);
        let auth = cfg.authority.as_ref().unwrap();
        verify_bundle_signing_key_ratification_v2(mk_v2_inputs(
            &v2,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .expect("v2 must still verify after JSON round-trip");
    }
}
