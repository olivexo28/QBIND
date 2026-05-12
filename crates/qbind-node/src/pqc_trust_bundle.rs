//! Run 050/051 (C4 piece: PQC transport trust-anchor lifecycle —
//! foundation + signed-bundle layer): structured, environment-bound,
//! canonically-hashable PQC trust-anchor bundle with ML-DSA-44
//! signed-bundle verification.
//!
//! This is the smallest production-honest replacement for the pre-Run-050
//! "ad hoc static `--p2p-trusted-root` only" surface. It introduces:
//!
//! - per-environment binding (DevNet / TestNet / MainNet) so that a
//!   DevNet bundle cannot be loaded on TestNet or MainNet and vice versa;
//! - per-root validity windows (`not_before` / `not_after`) and
//!   `active | retired | revoked` status, evaluated at load time;
//! - explicit revocation entries that fail closed regardless of the
//!   root's own status (defence in depth);
//! - deterministic canonical encoding + SHA3-256 bundle fingerprint
//!   suitable for `/metrics` and startup logs;
//! - DevNet-unsigned scaffolding only; TestNet and MainNet REFUSE to
//!   load an unsigned bundle. Signed-bundle (ML-DSA-44) verification
//!   itself is intentionally NOT implemented in this layer and is
//!   tracked as the remaining C4 piece in
//!   `docs/whitepaper/contradiction.md`.
//!
//! # Strict scope
//!
//! - **PQC-only**: only ML-DSA-44 (`suite_id = 100`) is accepted for
//!   trust-anchor roots. Any other suite id fails closed at parse time
//!   (same discipline as `pqc_root_config::parse_one_pqc_trusted_root_spec`).
//! - **No classical fallback. No DummySig fallback. No silent
//!   downgrade.** A malformed / expired / wrong-environment / unsigned-
//!   in-TestNet-or-MainNet bundle never silently falls back to the
//!   CLI `--p2p-trusted-root` path; the caller fails closed.
//! - **No KEMTLS / consensus / B14 redesign.** This module is a
//!   *load-time* validation and lookup layer that produces the same
//!   `PqcTrustedRoot` shape consumed by the rest of the transport
//!   stack today.
//!
//! # Trust separation
//!
//! - The transport leaf-cert ML-DSA-44 root key is the *transport*
//!   trust anchor.
//! - The bundle-signing key (when signature support lands) MUST NOT
//!   be the same key as a transport-root key. Reusing a transport
//!   root for bundle signatures would conflate "this validator can
//!   sign network delegation certs" with "this party can change the
//!   set of trusted networks roots" — that's bad trust separation
//!   by default. The struct shape below intentionally distinguishes
//!   `signing_key_id` from `root_id`s in `roots`.
//!
//! # Signature model (Run 051)
//!
//! - **DevNet**: unsigned bundles are accepted (Run 050 scaffolding).
//!   Signed DevNet bundles are *verified* against the configured
//!   bundle-signing key list; a signed bundle with no configured
//!   signing key, an unknown signing-key id, an unsupported suite, a
//!   malformed signature, or a bad signature all fail closed.
//! - **TestNet / MainNet**: unsigned bundles are REFUSED at load time
//!   (same as Run 050). Signed bundles are verified against the
//!   configured bundle-signing key list; the same fail-closed
//!   conditions as DevNet apply. A TestNet/MainNet bundle whose
//!   signature is `None` is rejected with `UnsignedBundleNotAllowed`,
//!   not with a "verification not implemented" message.
//!
//! # Signing preimage and domain separation
//!
//! The signing preimage is:
//!
//! ```text
//! b"QBIND:pqc-trust-bundle-signature:v1" || canonical_json(bundle{signature: None})
//! ```
//!
//! i.e. the bundle is canonicalised through `serde_json::to_vec`
//! exactly as for the fingerprint, with the `signature` envelope
//! stripped, and a distinct signing-domain-separator string is
//! prepended so this preimage cannot collide with any other digest
//! the project uses (transport cert digest, bundle fingerprint, etc).
//! See [`canonical_signing_bytes`].
//!
//! # Run 050 boundary preserved
//!
//! All Run 050 fail-closed conditions (wrong environment, validity
//! windows, root status, duplicates, unsupported suite, revocation
//! list consistency, schema version, signing_key_id collides with a
//! transport `root_id`) continue to hold *before* signature
//! verification is attempted, so an attacker cannot exercise the
//! verifier with a malformed envelope.

use std::collections::HashSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use qbind_crypto::{
    MlDsa44Backend, ML_DSA_44_PUBLIC_KEY_SIZE, ML_DSA_44_SIGNATURE_SIZE,
};
use qbind_types::{ChainId, NetworkEnvironment};

use crate::pqc_root_config::{PqcTrustedRoot, PQC_TRANSPORT_SUITE_ML_DSA_44};

/// Domain separator for ML-DSA-44 trust-bundle signatures. Distinct
/// from the bundle fingerprint domain separator (`QBIND:pqc-trust-bundle-fp:v1`)
/// so a fingerprint hash and a signature preimage can never collide.
pub const TRUST_BUNDLE_SIGNATURE_DOMAIN_SEPARATOR: &[u8] =
    b"QBIND:pqc-trust-bundle-signature:v1";

/// Environment label embedded in a bundle. Mirrors
/// [`qbind_types::NetworkEnvironment`] but is serialised in a
/// canonical lowercase form so that bundle files written for one
/// runtime version are stable across versions.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum TrustBundleEnvironment {
    Devnet,
    Testnet,
    Mainnet,
}

impl TrustBundleEnvironment {
    /// Numeric encoding used in `/metrics` (`qbind_p2p_pqc_trust_bundle_environment`).
    /// Stable: 0=devnet, 1=testnet, 2=mainnet.
    pub fn metric_code(&self) -> u64 {
        match self {
            Self::Devnet => 0,
            Self::Testnet => 1,
            Self::Mainnet => 2,
        }
    }

    /// Bridge to the runtime's [`NetworkEnvironment`] enum used by the
    /// rest of the node (CLI, profiles, genesis).
    pub fn matches_runtime(&self, env: NetworkEnvironment) -> bool {
        matches!(
            (self, env),
            (Self::Devnet, NetworkEnvironment::Devnet)
                | (Self::Testnet, NetworkEnvironment::Testnet)
                | (Self::Mainnet, NetworkEnvironment::Mainnet)
        )
    }

    pub fn from_runtime(env: NetworkEnvironment) -> Self {
        match env {
            NetworkEnvironment::Devnet => Self::Devnet,
            NetworkEnvironment::Testnet => Self::Testnet,
            NetworkEnvironment::Mainnet => Self::Mainnet,
        }
    }
}

impl std::fmt::Display for TrustBundleEnvironment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Devnet => f.write_str("devnet"),
            Self::Testnet => f.write_str("testnet"),
            Self::Mainnet => f.write_str("mainnet"),
        }
    }
}

/// Lifecycle status of a single trust-anchor root entry. Mirrors the
/// task definition exactly.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum RootStatus {
    /// Root is in active rotation and accepted for cert verification.
    Active,
    /// Root has been rotated out of service but is still recognised
    /// for audit purposes. Treated identically to a revoked root for
    /// verification: not accepted.
    Retired,
    /// Root has been explicitly revoked (compromise, retirement with
    /// prejudice, etc.). Not accepted for any cert verification.
    Revoked,
}

impl RootStatus {
    /// Returns true iff this status, by itself, would allow the root
    /// to be used as a trust anchor (validity-window and revocation-
    /// list checks happen separately).
    pub fn is_acceptable(&self) -> bool {
        matches!(self, Self::Active)
    }
}

/// One trust-anchor root entry in a [`TrustBundle`].
///
/// All hex fields are lowercase (matches the rest of QBIND's hex
/// parsing discipline — see `pqc_root_config::decode_hex_var`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustBundleRoot {
    /// 32-byte stable identifier (64 lowercase hex chars).
    pub root_id: String,
    /// ML-DSA suite id. Today only `100` (ML-DSA-44) is accepted; any
    /// other value fails closed at validation time. Held as `u8`
    /// rather than an enum to keep the JSON shape stable across
    /// future PQC suite additions.
    pub suite_id: u8,
    /// Full ML-DSA-44 public key, lowercase hex.
    pub root_pk: String,
    /// Lifecycle status (see [`RootStatus`]).
    pub status: RootStatus,
    /// Per-root validity window start (Unix seconds). A root with
    /// `not_before > validation_time` is rejected with the
    /// `RootNotYetValid` error.
    pub not_before: u64,
    /// Per-root validity window end (Unix seconds). A root with
    /// `not_after < validation_time` is rejected with the
    /// `RootExpired` error. Use `u64::MAX` for "no upper bound".
    pub not_after: u64,
    /// Optional activation epoch / height. Recorded in the bundle for
    /// future runtime-aware activation but NOT yet consulted by the
    /// transport. Documented in evidence as not yet enforced.
    #[serde(default)]
    pub activation_epoch: Option<u64>,
    #[serde(default)]
    pub activation_height: Option<u64>,
}

/// One revocation entry in a [`TrustBundle`]. Defence in depth: a
/// revocation entry overrides whatever `status` the corresponding
/// `roots[i]` happens to carry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustBundleRevocation {
    /// Revoked root id (64 lowercase hex chars). Matches a
    /// `TrustBundleRoot::root_id`. Mandatory.
    pub root_id: String,
    /// Optional revoked validator leaf cert fingerprint (hex). Carried
    /// in the schema for the future leaf-level revocation layer but
    /// NOT enforced in Run 050 — recorded honestly under "remaining"
    /// in evidence.
    #[serde(default)]
    pub leaf_cert_fingerprint: Option<String>,
    /// Free-form reason code (e.g. `"compromise"`, `"rotation"`,
    /// `"superseded"`). Logged on rejection.
    pub reason: String,
    /// Effective-from time (Unix seconds). Revocations whose
    /// `effective_from > validation_time` are NOT yet active. This is
    /// the smallest safe shape that supports planned rotation
    /// windows.
    pub effective_from: u64,
}

/// Top-level trust bundle artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustBundle {
    /// Schema version. Currently `1`. Anything else fails closed.
    pub bundle_version: u32,
    /// Target environment. MUST match the runtime environment or
    /// loading fails closed (`WrongEnvironment`).
    pub environment: TrustBundleEnvironment,
    /// Optional chain-id (hex) when available. When present, it MUST
    /// match the runtime chain id or loading fails closed.
    #[serde(default)]
    pub chain_id: Option<String>,
    /// Bundle creation time (Unix seconds). Informational.
    pub generated_at: u64,
    /// Bundle validity start (Unix seconds).
    pub valid_from: u64,
    /// Bundle validity end (Unix seconds). Use a sentinel like
    /// `u64::MAX` for "no upper bound" only on DevNet test artifacts;
    /// production-honest bundles should carry a real finite window.
    pub valid_until: u64,
    /// Monotonic sequence number. Two bundles for the same
    /// environment must use increasing sequence numbers; this layer
    /// records but does not enforce monotonicity (no persistent
    /// runtime state is mutated by this module).
    pub sequence: u64,
    /// Trust-anchor roots.
    pub roots: Vec<TrustBundleRoot>,
    /// Explicit revocation list (root-level).
    #[serde(default)]
    pub revocations: Vec<TrustBundleRevocation>,
    /// Optional bundle signature (Run 050: parsed but NOT verified).
    /// When present in TestNet / MainNet, loading fails closed with
    /// `SignedBundleVerificationNotImplemented` (precise error so
    /// operators can find the C4 piece in `contradiction.md`).
    #[serde(default)]
    pub signature: Option<TrustBundleSignature>,
}

/// Bundle signature envelope. Stored on disk in the canonical bundle
/// JSON. Not verified in Run 050 (see `TrustBundleError::SignedBundleVerificationNotImplemented`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustBundleSignature {
    /// Stable identifier of the bundle-signing key (64 lowercase hex
    /// chars). MUST NOT collide with any `roots[i].root_id`.
    pub signing_key_id: String,
    /// Signature suite (today: `100` for ML-DSA-44; anything else
    /// fails closed once verification lands).
    pub suite_id: u8,
    /// Raw signature bytes (hex).
    pub sig_bytes: String,
}

// ---------------------------------------------------------------------
// Run 051: bundle-signing key list (trust-separated from transport
// roots). Verifies the `signature` envelope above.
// ---------------------------------------------------------------------

/// One configured bundle-signing verification key. Parsed from the
/// repeatable `--p2p-trust-bundle-signing-key KEYID:SUITE:PK` CLI flag.
///
/// The key set lives **separately** from any `--p2p-trusted-root` /
/// `TrustBundleRoot` — a transport-root key MUST NOT also be a
/// bundle-signing key. The cross-source collision check is enforced
/// at startup in `main.rs`; the bundle's own `signature.signing_key_id`
/// vs. `roots[i].root_id` collision is enforced by [`TrustBundle::validate_at`]
/// (Run 050 invariant, preserved).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleSigningKey {
    /// 32-byte stable id, lowercase-hex form preserved for log/metric
    /// surfaces.
    pub key_id_bytes: [u8; 32],
    /// Signature suite. Today only `100` (ML-DSA-44) is accepted.
    pub suite_id: u8,
    /// Raw public-key bytes (length = `ML_DSA_44_PUBLIC_KEY_SIZE` for suite 100).
    pub pk_bytes: Vec<u8>,
}

impl BundleSigningKey {
    /// Short, log-safe id (first 8 hex chars). Never logs the public key.
    pub fn key_id_short(&self) -> String {
        let mut out = String::with_capacity(8);
        for b in &self.key_id_bytes[..4] {
            use std::fmt::Write;
            let _ = write!(out, "{:02x}", b);
        }
        out
    }

    /// Full 64-char lowercase hex id.
    pub fn key_id_hex(&self) -> String {
        let mut out = String::with_capacity(64);
        for b in &self.key_id_bytes {
            use std::fmt::Write;
            let _ = write!(out, "{:02x}", b);
        }
        out
    }
}

/// Set of configured bundle-signing keys, keyed by `key_id_bytes`.
/// Lookup is by exact id; duplicate ids are rejected at parse time.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BundleSigningKeySet {
    pub(crate) keys: Vec<BundleSigningKey>,
}

impl BundleSigningKeySet {
    /// Construct an empty set. Used by the DevNet-unsigned path and by
    /// the back-compat 3-arg `load_from_bytes` shim.
    pub fn empty() -> Self {
        Self { keys: Vec::new() }
    }

    /// Test/helper constructor: build a `BundleSigningKeySet` from a
    /// raw list of `BundleSigningKey` (no parsing). Caller is
    /// responsible for ensuring suite/length/duplicate-id invariants
    /// — the type-level invariants of `BundleSigningKey` (suite,
    /// pk length) are preserved, but no duplicate check is performed.
    /// Used by tests and by helpers that already have validated keys.
    #[doc(hidden)]
    pub fn from_keys_unchecked(keys: Vec<BundleSigningKey>) -> Self {
        Self { keys }
    }

    /// Test/helper accessor: push a key without de-dup checks. Used
    /// only by integration tests that simulate misconfiguration.
    #[doc(hidden)]
    pub fn push_key_unchecked(&mut self, key: BundleSigningKey) {
        self.keys.push(key);
    }

    /// Returns `true` iff no signing keys are configured.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Number of configured signing keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Iterator over configured keys (no public-key bytes in `Display`).
    pub fn iter(&self) -> impl Iterator<Item = &BundleSigningKey> {
        self.keys.iter()
    }

    /// Look up a signing key by canonical 32-byte id.
    pub fn lookup(&self, key_id: &[u8; 32]) -> Option<&BundleSigningKey> {
        self.keys.iter().find(|k| &k.key_id_bytes == key_id)
    }

    /// Parse one `KEYID:SUITE:PK` spec and push it into the set,
    /// enforcing strict validation and duplicate-id rejection.
    pub fn push_spec(&mut self, spec: &str) -> Result<(), BundleSigningKeySpecError> {
        let key = parse_bundle_signing_key_spec(spec)?;
        if self.keys.iter().any(|k| k.key_id_bytes == key.key_id_bytes) {
            return Err(BundleSigningKeySpecError::DuplicateKeyId(
                key.key_id_hex(),
            ));
        }
        self.keys.push(key);
        Ok(())
    }

    /// Parse a list of specs into a fresh set. Fails closed on the
    /// first malformed / duplicate entry.
    pub fn parse_specs(specs: &[String]) -> Result<Self, BundleSigningKeySpecError> {
        let mut out = Self::empty();
        for s in specs {
            out.push_spec(s)?;
        }
        Ok(out)
    }
}

/// Errors returned by [`BundleSigningKeySet::push_spec`] and friends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleSigningKeySpecError {
    /// Format mismatch (expected `KEYID:SUITE:PK` with exactly two
    /// colon separators; no trailing or empty fields).
    Malformed(String),
    /// Hex parse error in the `KEYID` or `PK` field.
    MalformedHex(String),
    /// Suite id was not `100` (ML-DSA-44).
    UnsupportedSuite(u8),
    /// `PK` decoded to the wrong length for the declared suite.
    WrongPublicKeyLength { expected: usize, actual: usize },
    /// Duplicate `KEYID` in the configured list.
    DuplicateKeyId(String),
}

impl std::fmt::Display for BundleSigningKeySpecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(s) => write!(
                f,
                "malformed --p2p-trust-bundle-signing-key spec {:?} (expected KEYID:SUITE:PK)",
                s
            ),
            Self::MalformedHex(s) => write!(
                f,
                "malformed --p2p-trust-bundle-signing-key hex: {}",
                s
            ),
            Self::UnsupportedSuite(s) => write!(
                f,
                "unsupported --p2p-trust-bundle-signing-key suite_id {} (only {} = ML-DSA-44 accepted)",
                s, PQC_TRANSPORT_SUITE_ML_DSA_44
            ),
            Self::WrongPublicKeyLength { expected, actual } => write!(
                f,
                "--p2p-trust-bundle-signing-key public key length mismatch (expected {} bytes, got {})",
                expected, actual
            ),
            Self::DuplicateKeyId(id) => write!(
                f,
                "duplicate --p2p-trust-bundle-signing-key id {} in configured set",
                id
            ),
        }
    }
}

impl std::error::Error for BundleSigningKeySpecError {}

/// Parse a single `KEYID:SUITE:PK` spec. Strict: exactly two colons,
/// no empty fields, hex must be lowercase-only via the same `nibble`
/// discipline as the rest of `pqc_trust_bundle`.
pub fn parse_bundle_signing_key_spec(
    spec: &str,
) -> Result<BundleSigningKey, BundleSigningKeySpecError> {
    let parts: Vec<&str> = spec.split(':').collect();
    if parts.len() != 3 {
        return Err(BundleSigningKeySpecError::Malformed(spec.to_string()));
    }
    let (keyid_str, suite_str, pk_str) = (parts[0], parts[1], parts[2]);
    if keyid_str.is_empty() || suite_str.is_empty() || pk_str.is_empty() {
        return Err(BundleSigningKeySpecError::Malformed(spec.to_string()));
    }
    let key_id_bytes = decode_hex_fixed_32(keyid_str)
        .map_err(|e| BundleSigningKeySpecError::MalformedHex(format!("KEYID: {}", e)))?;
    let suite_id: u8 = suite_str
        .parse()
        .map_err(|_| BundleSigningKeySpecError::Malformed(spec.to_string()))?;
    if suite_id != PQC_TRANSPORT_SUITE_ML_DSA_44 {
        return Err(BundleSigningKeySpecError::UnsupportedSuite(suite_id));
    }
    let pk_bytes = decode_hex_var(pk_str)
        .map_err(|e| BundleSigningKeySpecError::MalformedHex(format!("PK: {}", e)))?;
    if pk_bytes.len() != ML_DSA_44_PUBLIC_KEY_SIZE {
        return Err(BundleSigningKeySpecError::WrongPublicKeyLength {
            expected: ML_DSA_44_PUBLIC_KEY_SIZE,
            actual: pk_bytes.len(),
        });
    }
    Ok(BundleSigningKey {
        key_id_bytes,
        suite_id,
        pk_bytes,
    })
}

/// Errors returned by [`TrustBundle::load_from_path`] and
/// [`TrustBundle::validate_at`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustBundleError {
    /// I/O error reading the bundle file (no path bytes are logged;
    /// only the path string supplied by the operator and the OS error
    /// kind).
    Io(String),
    /// JSON parse error.
    Malformed(String),
    /// Unsupported `bundle_version`.
    UnsupportedSchemaVersion(u32),
    /// Runtime environment did not match `bundle.environment`.
    WrongEnvironment {
        expected: TrustBundleEnvironment,
        found: TrustBundleEnvironment,
    },
    /// Bundle `chain_id` was present but not a supported canonical
    /// 64-bit lowercase-hex representation.
    InvalidChainIdFormat(String),
    /// Runtime chain id did not match `bundle.chain_id`.
    WrongChainId {
        expected: ChainId,
        found: ChainId,
    },
    /// `valid_from > valid_until` (inverted window).
    InvalidBundleValidityWindow,
    /// `validation_time < valid_from`.
    BundleNotYetValid,
    /// `validation_time > valid_until`.
    BundleExpired,
    /// At least one root has `not_before > not_after`.
    InvalidRootValidityWindow(String),
    /// Root is not yet valid at `validation_time`.
    RootNotYetValid(String),
    /// Root is expired at `validation_time`.
    RootExpired(String),
    /// Two `roots[i]` carried the same `root_id`.
    DuplicateRootId(String),
    /// A root entry used a suite id other than ML-DSA-44 (`100`).
    UnsupportedSuite { root_id: String, suite_id: u8 },
    /// Hex decoding failure (root id, public key, or signing key id).
    MalformedHex(String),
    /// Root public key length did not match the declared suite.
    MalformedRootPublicKey {
        root_id: String,
        expected: usize,
        actual: usize,
    },
    /// A revocation entry referenced a `root_id` not present in
    /// `roots`. (Defence in depth — operators are required to keep
    /// revocations consistent with the root list. Stricter than
    /// strictly necessary but it catches typos.)
    RevocationReferencesUnknownRoot(String),
    /// Two revocations referenced the same `root_id` (the second
    /// silent entry would be ignored — fail closed instead).
    DuplicateRevocation(String),
    /// `signing_key_id` collided with a `roots[i].root_id`. Refused
    /// by the trust-separation policy documented at the top of this
    /// module.
    SigningKeyCollidesWithRootId(String),
    /// The bundle is unsigned but the target environment is
    /// TestNet or MainNet, both of which require a signature.
    UnsignedBundleNotAllowed(TrustBundleEnvironment),
    /// Run 051: bundle carries a signature but no bundle-signing key
    /// matching `signature.signing_key_id` is configured.
    MissingSigningKey { signing_key_id: String },
    /// Run 051: bundle signature suite is not supported. Today only
    /// `100` (ML-DSA-44) is accepted.
    UnsupportedSignatureSuite { signing_key_id: String, suite_id: u8 },
    /// Run 051: bundle signature suite differs from the configured
    /// signing key's suite (cross-suite confusion). Fail closed.
    SignatureSuiteMismatch {
        signing_key_id: String,
        bundle_suite_id: u8,
        configured_suite_id: u8,
    },
    /// Run 051: bundle signature bytes did not decode to the
    /// declared suite's signature length / contained non-hex chars.
    MalformedSignatureBytes {
        signing_key_id: String,
        reason: String,
    },
    /// Run 051: ML-DSA-44 signature verification failed. Tampered
    /// bundle, wrong signing key (which collided on id but not pk),
    /// or any forged envelope falls here. Fail closed.
    BadSignature { signing_key_id: String },
    /// Run 051 deprecated boundary (kept for source-level back-compat
    /// with Run 050 test fixtures; not produced by the new verify
    /// path). Indicates a signed bundle reached the validator before
    /// the signed-bundle verification feature was wired in.
    #[doc(hidden)]
    SignedBundleVerificationNotImplemented,
    /// Run 052: a revocation entry carried a malformed
    /// `leaf_cert_fingerprint` field (not 64 lowercase-hex chars, or
    /// hex-decode failure). Refusing the whole bundle catches operator
    /// typos rather than silently dropping the entry.
    MalformedLeafFingerprint {
        root_id: String,
        reason: String,
    },
}

impl std::fmt::Display for TrustBundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(s) => write!(f, "trust bundle io: {}", s),
            Self::Malformed(s) => write!(f, "malformed trust bundle: {}", s),
            Self::UnsupportedSchemaVersion(v) => {
                write!(f, "unsupported trust bundle schema version: {}", v)
            }
            Self::WrongEnvironment { expected, found } => write!(
                f,
                "trust bundle environment mismatch (expected {}, bundle declares {})",
                expected, found
            ),
            Self::InvalidChainIdFormat(s) => write!(
                f,
                "trust bundle chain_id has invalid format: {} (expected 16 lowercase hex chars, optionally prefixed by 0x or chain_)",
                s
            ),
            Self::WrongChainId { expected, found } => write!(
                f,
                "trust bundle chain_id mismatch (expected {}, bundle declares {})",
                expected, found
            ),
            Self::InvalidBundleValidityWindow => f.write_str(
                "trust bundle valid_from > valid_until (inverted window — fails closed)",
            ),
            Self::BundleNotYetValid => f.write_str("trust bundle is not yet valid"),
            Self::BundleExpired => f.write_str("trust bundle is expired"),
            Self::InvalidRootValidityWindow(id) => write!(
                f,
                "trust bundle root {} has not_before > not_after",
                id
            ),
            Self::RootNotYetValid(id) => {
                write!(f, "trust bundle root {} is not yet valid", id)
            }
            Self::RootExpired(id) => {
                write!(f, "trust bundle root {} is expired", id)
            }
            Self::DuplicateRootId(id) => {
                write!(f, "trust bundle has duplicate root_id {}", id)
            }
            Self::UnsupportedSuite { root_id, suite_id } => write!(
                f,
                "trust bundle root {} uses unsupported suite_id {} (only {} = ML-DSA-44 accepted)",
                root_id, suite_id, PQC_TRANSPORT_SUITE_ML_DSA_44
            ),
            Self::MalformedHex(s) => write!(f, "trust bundle malformed hex: {}", s),
            Self::MalformedRootPublicKey {
                root_id,
                expected,
                actual,
            } => write!(
                f,
                "trust bundle root {} has malformed root_pk (expected {} bytes, got {})",
                root_id, expected, actual
            ),
            Self::RevocationReferencesUnknownRoot(id) => write!(
                f,
                "trust bundle revocation references unknown root_id {}",
                id
            ),
            Self::DuplicateRevocation(id) => {
                write!(f, "trust bundle has duplicate revocation for root_id {}", id)
            }
            Self::SigningKeyCollidesWithRootId(id) => write!(
                f,
                "trust bundle signing_key_id {} collides with a transport root_id \
                 (trust-separation policy fails closed)",
                id
            ),
            Self::UnsignedBundleNotAllowed(env) => write!(
                f,
                "trust bundle is unsigned but environment {} requires a signed bundle. \
                 See docs/whitepaper/contradiction.md C4 (signed root distribution).",
                env
            ),
            Self::MissingSigningKey { signing_key_id } => write!(
                f,
                "trust bundle signature references signing_key_id {} but no matching \
                 --p2p-trust-bundle-signing-key was configured (fail closed)",
                signing_key_id
            ),
            Self::UnsupportedSignatureSuite { signing_key_id, suite_id } => write!(
                f,
                "trust bundle signature for signing_key_id {} uses unsupported suite_id {} \
                 (only {} = ML-DSA-44 accepted)",
                signing_key_id, suite_id, PQC_TRANSPORT_SUITE_ML_DSA_44
            ),
            Self::SignatureSuiteMismatch {
                signing_key_id,
                bundle_suite_id,
                configured_suite_id,
            } => write!(
                f,
                "trust bundle signature for signing_key_id {} declares suite_id {} but the \
                 configured signing key uses suite_id {} (cross-suite mismatch fails closed)",
                signing_key_id, bundle_suite_id, configured_suite_id
            ),
            Self::MalformedSignatureBytes { signing_key_id, reason } => write!(
                f,
                "trust bundle signature for signing_key_id {} has malformed sig_bytes: {}",
                signing_key_id, reason
            ),
            Self::BadSignature { signing_key_id } => write!(
                f,
                "trust bundle ML-DSA-44 signature verification failed for signing_key_id {} \
                 (tampered bundle or forged envelope — fail closed)",
                signing_key_id
            ),
            Self::SignedBundleVerificationNotImplemented => f.write_str(
                "trust bundle carries a signature but signed-bundle verification is not \
                 wired (legacy Run 050 boundary; should not appear in Run 051+).",
            ),
            Self::MalformedLeafFingerprint { root_id, reason } => write!(
                f,
                "trust bundle revocation for root_id {} has malformed leaf_cert_fingerprint: {}",
                root_id, reason
            ),
        }
    }
}

impl std::error::Error for TrustBundleError {}

/// Result of a successful load + validate. Carries the typed bundle,
/// the deterministic fingerprint, the parsed list of acceptable
/// trust-anchor roots (status=Active, in validity window, not
/// revoked), and the parsed set of revoked root ids.
#[derive(Debug, Clone)]
pub struct LoadedTrustBundle {
    pub bundle: TrustBundle,
    pub fingerprint: [u8; 32],
    pub active_roots: Vec<PqcTrustedRoot>,
    /// Set of revoked root ids (32-byte canonical form). A root id
    /// that appears here MUST NOT be accepted for cert verification,
    /// even if it also appears in `active_roots` (defence in depth —
    /// the construction below already filters them out, this field is
    /// retained for lookup at verify time and for metrics).
    pub revoked_root_ids: HashSet<[u8; 32]>,
    /// Run 052: set of revoked validator leaf-cert fingerprints
    /// (32-byte SHA3-256 of the canonical wire encoding of the leaf
    /// `NetworkDelegationCert`; see [`cert_leaf_fingerprint`]). A leaf
    /// fingerprint that appears here MUST be rejected at PQC cert
    /// verification time, fail closed, regardless of whether the leaf
    /// otherwise verifies against a still-active root. Populated only
    /// from `revocations[i].leaf_cert_fingerprint` entries whose
    /// `effective_from <= validation_time_secs`; future-dated leaf
    /// revocations are recorded but not yet active.
    pub revoked_leaf_fingerprints: HashSet<[u8; 32]>,
    /// Run 051: result of the ML-DSA-44 signed-bundle verification
    /// step. `Unsigned` for DevNet unsigned bundles; `Verified` for
    /// any signed bundle that successfully verified against the
    /// configured signing-key set. The validator never returns
    /// `LoadedTrustBundle` with a failed signature — failures fail
    /// closed in `validate_at_with_signing_keys`.
    pub signature_status: BundleSignatureStatus,
}

/// Outcome of the signed-bundle verification step on a successfully
/// loaded bundle. (Failed verifications fail closed inside
/// [`TrustBundle::validate_at_with_signing_keys`] and never reach
/// this type.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleSignatureStatus {
    /// Bundle carried no signature envelope (DevNet unsigned).
    Unsigned,
    /// Bundle signature was successfully verified by the configured
    /// signing key. The `signing_key_id` is the 64-char lowercase hex
    /// id used at the wire boundary.
    Verified { signing_key_id: String },
}

impl BundleSignatureStatus {
    /// Returns `true` iff the bundle was verified.
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }
}

impl LoadedTrustBundle {
    /// Short, log-safe fingerprint (first 8 hex chars).
    pub fn fingerprint_short(&self) -> String {
        let mut out = String::with_capacity(8);
        for b in &self.fingerprint[..4] {
            use std::fmt::Write;
            let _ = write!(out, "{:02x}", b);
        }
        out
    }

    /// Full lowercase hex fingerprint (64 chars).
    pub fn fingerprint_hex(&self) -> String {
        let mut out = String::with_capacity(64);
        for b in &self.fingerprint {
            use std::fmt::Write;
            let _ = write!(out, "{:02x}", b);
        }
        out
    }

    pub fn environment(&self) -> TrustBundleEnvironment {
        self.bundle.environment
    }

    pub fn active_root_count(&self) -> usize {
        self.active_roots.len()
    }

    pub fn revoked_root_count(&self) -> usize {
        self.revoked_root_ids.len()
    }

    /// Returns true iff the given root id is on the bundle's
    /// revocation list. Used by the transport-root resolver to fail
    /// closed at verify time even if the same id was somehow also in
    /// the active set.
    pub fn is_root_revoked(&self, root_id: &[u8; 32]) -> bool {
        self.revoked_root_ids.contains(root_id)
    }

    /// Run 052: returns true iff the given leaf cert fingerprint (the
    /// SHA3-256 of the leaf `NetworkDelegationCert` canonical wire
    /// encoding; see [`cert_leaf_fingerprint`]) is on the bundle's
    /// currently-active leaf revocation list. Used by the PQC cert
    /// verify path to fail closed on a revoked leaf cert.
    pub fn is_leaf_revoked(&self, leaf_fingerprint: &[u8; 32]) -> bool {
        self.revoked_leaf_fingerprints.contains(leaf_fingerprint)
    }

    /// Run 052: count of currently-active leaf revocations.
    pub fn revoked_leaf_fingerprint_count(&self) -> usize {
        self.revoked_leaf_fingerprints.len()
    }
}

impl TrustBundle {
    /// Currently supported schema version.
    pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;

    /// Load + validate from a JSON file on disk. Back-compat shim with
    /// an empty `BundleSigningKeySet`: a DevNet unsigned bundle still
    /// loads, but any signed bundle now fails closed with
    /// `MissingSigningKey` rather than the Run 050
    /// `SignedBundleVerificationNotImplemented` placeholder.
    pub fn load_from_path(
        path: &Path,
        expected_env: NetworkEnvironment,
        validation_time_secs: u64,
    ) -> Result<LoadedTrustBundle, TrustBundleError> {
        Self::load_from_path_with_signing_keys(
            path,
            expected_env,
            validation_time_secs,
            &BundleSigningKeySet::empty(),
        )
    }

    /// Run 051: load + validate + verify signature from a JSON file
    /// on disk against the supplied signing-key set.
    pub fn load_from_path_with_signing_keys(
        path: &Path,
        expected_env: NetworkEnvironment,
        validation_time_secs: u64,
        signing_keys: &BundleSigningKeySet,
    ) -> Result<LoadedTrustBundle, TrustBundleError> {
        Self::load_from_path_with_signing_keys_and_chain_id(
            path,
            expected_env,
            expected_env.chain_id(),
            validation_time_secs,
            signing_keys,
        )
    }

    /// Run 053: load + validate + verify signature from a JSON file,
    /// additionally enforcing a present bundle `chain_id` against the
    /// runtime chain id. Callers with custom chain ids should use this
    /// entry point; the older shim uses the canonical chain id for the
    /// selected environment.
    pub fn load_from_path_with_signing_keys_and_chain_id(
        path: &Path,
        expected_env: NetworkEnvironment,
        expected_chain_id: ChainId,
        validation_time_secs: u64,
        signing_keys: &BundleSigningKeySet,
    ) -> Result<LoadedTrustBundle, TrustBundleError> {
        let bytes = std::fs::read(path)
            .map_err(|e| TrustBundleError::Io(format!("{}: {}", path.display(), e)))?;
        Self::load_from_bytes_with_signing_keys_and_chain_id(
            &bytes,
            expected_env,
            expected_chain_id,
            validation_time_secs,
            signing_keys,
        )
    }

    /// Load + validate from in-memory bytes (back-compat shim;
    /// empty signing-key set).
    pub fn load_from_bytes(
        bytes: &[u8],
        expected_env: NetworkEnvironment,
        validation_time_secs: u64,
    ) -> Result<LoadedTrustBundle, TrustBundleError> {
        Self::load_from_bytes_with_signing_keys(
            bytes,
            expected_env,
            validation_time_secs,
            &BundleSigningKeySet::empty(),
        )
    }

    /// Run 051: load + validate + verify signature from in-memory
    /// bytes against the supplied signing-key set.
    pub fn load_from_bytes_with_signing_keys(
        bytes: &[u8],
        expected_env: NetworkEnvironment,
        validation_time_secs: u64,
        signing_keys: &BundleSigningKeySet,
    ) -> Result<LoadedTrustBundle, TrustBundleError> {
        Self::load_from_bytes_with_signing_keys_and_chain_id(
            bytes,
            expected_env,
            expected_env.chain_id(),
            validation_time_secs,
            signing_keys,
        )
    }

    /// Run 053: in-memory load + validate with explicit runtime chain id.
    pub fn load_from_bytes_with_signing_keys_and_chain_id(
        bytes: &[u8],
        expected_env: NetworkEnvironment,
        expected_chain_id: ChainId,
        validation_time_secs: u64,
        signing_keys: &BundleSigningKeySet,
    ) -> Result<LoadedTrustBundle, TrustBundleError> {
        let bundle: TrustBundle = serde_json::from_slice(bytes)
            .map_err(|e| TrustBundleError::Malformed(format!("{}", e)))?;
        bundle.validate_at_with_signing_keys_and_chain_id(
            expected_env,
            expected_chain_id,
            validation_time_secs,
            signing_keys,
        )
    }

    /// Validate and produce [`LoadedTrustBundle`] (back-compat shim;
    /// empty signing-key set).
    pub fn validate_at(
        self,
        expected_env: NetworkEnvironment,
        validation_time_secs: u64,
    ) -> Result<LoadedTrustBundle, TrustBundleError> {
        self.validate_at_with_signing_keys(
            expected_env,
            validation_time_secs,
            &BundleSigningKeySet::empty(),
        )
    }

    /// Run 051: validate the bundle (schema, environment, validity
    /// window, root status / windows, revocation consistency,
    /// trust-separation) AND verify the ML-DSA-44 signature against
    /// the supplied signing-key set. Pure: takes no I/O.
    pub fn validate_at_with_signing_keys(
        self,
        expected_env: NetworkEnvironment,
        validation_time_secs: u64,
        signing_keys: &BundleSigningKeySet,
    ) -> Result<LoadedTrustBundle, TrustBundleError> {
        self.validate_at_with_signing_keys_and_chain_id(
            expected_env,
            expected_env.chain_id(),
            validation_time_secs,
            signing_keys,
        )
    }

    /// Run 053: validate with explicit runtime chain id. A missing
    /// bundle `chain_id` remains accepted for Run-050 compatibility;
    /// a present value is parsed strictly and compared fail-closed.
    pub fn validate_at_with_signing_keys_and_chain_id(
        self,
        expected_env: NetworkEnvironment,
        expected_chain_id: ChainId,
        validation_time_secs: u64,
        signing_keys: &BundleSigningKeySet,
    ) -> Result<LoadedTrustBundle, TrustBundleError> {
        // 1. Schema version.
        if self.bundle_version != Self::SUPPORTED_SCHEMA_VERSION {
            return Err(TrustBundleError::UnsupportedSchemaVersion(
                self.bundle_version,
            ));
        }

        // 2. Environment binding.
        let expected = TrustBundleEnvironment::from_runtime(expected_env);
        if self.environment != expected {
            return Err(TrustBundleError::WrongEnvironment {
                expected,
                found: self.environment,
            });
        }

        // 2b. Chain-id binding. Run 050 recorded the field without
        // enforcing it; Run 053 enforces it when present, while
        // preserving absent/null compatibility for existing DevNet
        // fixtures and operator bundles.
        if let Some(raw_chain_id) = self.chain_id.as_deref() {
            let found = parse_bundle_chain_id(raw_chain_id)
                .map_err(TrustBundleError::InvalidChainIdFormat)?;
            if found != expected_chain_id {
                return Err(TrustBundleError::WrongChainId {
                    expected: expected_chain_id,
                    found,
                });
            }
        }

        // 3. Signature model boundary (Run 051).
        //
        //    DevNet      -> unsigned OK; signed verified against the
        //                   configured signing-key set; missing key,
        //                   bad signature, malformed bytes,
        //                   unsupported suite, or suite mismatch all
        //                   fail closed.
        //    TestNet     -> unsigned REFUSED; signed verified
        //                   (same fail-closed conditions as DevNet).
        //    MainNet     -> unsigned REFUSED; signed verified
        //                   (same fail-closed conditions as DevNet).
        //
        //    Note: actual ML-DSA-44 verification is deferred to step
        //    7b below, AFTER the structural validations (schema,
        //    window, root status, revocations, trust-separation) so
        //    that we never invoke the verifier with a malformed
        //    envelope. The early branch here only catches "unsigned
        //    bundle on a network that requires a signature".
        if self.signature.is_none() {
            match self.environment {
                TrustBundleEnvironment::Devnet => {
                    // OK — DevNet unsigned scaffolding (preserved).
                }
                env @ (TrustBundleEnvironment::Testnet | TrustBundleEnvironment::Mainnet) => {
                    return Err(TrustBundleError::UnsignedBundleNotAllowed(env));
                }
            }
        }

        // 4. Bundle validity window.
        if self.valid_from > self.valid_until {
            return Err(TrustBundleError::InvalidBundleValidityWindow);
        }
        if validation_time_secs < self.valid_from {
            return Err(TrustBundleError::BundleNotYetValid);
        }
        if validation_time_secs > self.valid_until {
            return Err(TrustBundleError::BundleExpired);
        }

        // 5. Parse + canonicalise each root. Strict shape (mirrors
        //    `pqc_root_config::parse_one_pqc_trusted_root_spec`).
        let mut seen_root_ids: HashSet<[u8; 32]> = HashSet::new();
        let mut parsed_roots: Vec<(TrustBundleRoot, [u8; 32], Vec<u8>)> =
            Vec::with_capacity(self.roots.len());
        for r in &self.roots {
            if r.suite_id != PQC_TRANSPORT_SUITE_ML_DSA_44 {
                return Err(TrustBundleError::UnsupportedSuite {
                    root_id: r.root_id.clone(),
                    suite_id: r.suite_id,
                });
            }
            if r.not_before > r.not_after {
                return Err(TrustBundleError::InvalidRootValidityWindow(
                    r.root_id.clone(),
                ));
            }
            let id_bytes = decode_hex_fixed_32(&r.root_id)
                .map_err(|e| TrustBundleError::MalformedHex(format!("root_id {}: {}", r.root_id, e)))?;
            let pk_bytes = decode_hex_var(&r.root_pk).map_err(|e| {
                TrustBundleError::MalformedHex(format!("root_pk for {}: {}", r.root_id, e))
            })?;
            if pk_bytes.len() != ML_DSA_44_PUBLIC_KEY_SIZE {
                return Err(TrustBundleError::MalformedRootPublicKey {
                    root_id: r.root_id.clone(),
                    expected: ML_DSA_44_PUBLIC_KEY_SIZE,
                    actual: pk_bytes.len(),
                });
            }
            if !seen_root_ids.insert(id_bytes) {
                return Err(TrustBundleError::DuplicateRootId(r.root_id.clone()));
            }
            parsed_roots.push((r.clone(), id_bytes, pk_bytes));
        }

        // 6. Parse + canonicalise revocations. Each must reference a
        //    known root id.
        //
        //    Run 052 semantics — the existing `revocations[]` schema
        //    is now interpreted as a *scoped* revocation list, with
        //    the scope chosen by the optional `leaf_cert_fingerprint`
        //    field:
        //
        //    - `leaf_cert_fingerprint = None`  → **root-level** revocation.
        //       Excludes the root from the active set (Run 050 behaviour;
        //       preserved). Duplicate root-level revocations of the
        //       same `root_id` fail closed (`DuplicateRevocation`).
        //    - `leaf_cert_fingerprint = Some(fp)` → **leaf-level**
        //       revocation. Revokes the specific leaf cert whose
        //       canonical fingerprint (see [`cert_leaf_fingerprint`])
        //       equals `fp`. Does NOT exclude the root; the root
        //       remains usable for other (still-valid) leaf certs.
        //       Multiple leaf-level entries under the same `root_id`
        //       are allowed (one per leaf); duplicate leaf fingerprints
        //       (same 32-byte fp under any root) fail closed.
        //
        //    Malformed `leaf_cert_fingerprint` hex fails closed
        //    (`MalformedLeafFingerprint`) so an operator typo cannot
        //    silently drop a leaf revocation.
        //
        //    Future-dated revocations (`effective_from > validation_time_secs`)
        //    are recorded but not yet active: they are excluded from
        //    `revoked_root_ids` AND from `revoked_leaf_fingerprints`.
        let mut revoked_root_ids: HashSet<[u8; 32]> = HashSet::new();
        let mut revoked_leaf_fingerprints: HashSet<[u8; 32]> = HashSet::new();
        let mut seen_root_level_revocations: HashSet<[u8; 32]> = HashSet::new();
        let mut seen_leaf_fingerprints: HashSet<[u8; 32]> = HashSet::new();
        for rev in &self.revocations {
            let id_bytes = decode_hex_fixed_32(&rev.root_id).map_err(|e| {
                TrustBundleError::MalformedHex(format!(
                    "revocation root_id {}: {}",
                    rev.root_id, e
                ))
            })?;
            if !seen_root_ids.contains(&id_bytes) {
                return Err(TrustBundleError::RevocationReferencesUnknownRoot(
                    rev.root_id.clone(),
                ));
            }
            match &rev.leaf_cert_fingerprint {
                None => {
                    // Root-level revocation. Run 050 behaviour preserved.
                    if !seen_root_level_revocations.insert(id_bytes) {
                        return Err(TrustBundleError::DuplicateRevocation(
                            rev.root_id.clone(),
                        ));
                    }
                    if rev.effective_from <= validation_time_secs {
                        revoked_root_ids.insert(id_bytes);
                    }
                }
                Some(leaf_fp_hex) => {
                    // Leaf-level revocation. Run 052 surface.
                    let leaf_fp_bytes =
                        decode_hex_fixed_32(leaf_fp_hex).map_err(|e| {
                            TrustBundleError::MalformedLeafFingerprint {
                                root_id: rev.root_id.clone(),
                                reason: e,
                            }
                        })?;
                    if !seen_leaf_fingerprints.insert(leaf_fp_bytes) {
                        return Err(TrustBundleError::DuplicateRevocation(
                            rev.root_id.clone(),
                        ));
                    }
                    if rev.effective_from <= validation_time_secs {
                        revoked_leaf_fingerprints.insert(leaf_fp_bytes);
                    }
                }
            }
        }

        // 7. Trust-separation: signing_key_id MUST NOT collide with
        //    any root_id. (Run 050 invariant; preserved.)
        let parsed_signing_id: Option<[u8; 32]> = if let Some(sig) = &self.signature {
            let signing_id_bytes = decode_hex_fixed_32(&sig.signing_key_id).map_err(|e| {
                TrustBundleError::MalformedHex(format!(
                    "signing_key_id {}: {}",
                    sig.signing_key_id, e
                ))
            })?;
            if seen_root_ids.contains(&signing_id_bytes) {
                return Err(TrustBundleError::SigningKeyCollidesWithRootId(
                    sig.signing_key_id.clone(),
                ));
            }
            Some(signing_id_bytes)
        } else {
            None
        };

        // 7b. Run 051: ML-DSA-44 signature verification. Only reached
        //     when the envelope has already passed every structural
        //     check above. Any failure here fails closed; we never
        //     return `LoadedTrustBundle` for a signed-but-unverified
        //     bundle.
        let signature_status: BundleSignatureStatus = match (&self.signature, parsed_signing_id) {
            (None, _) => BundleSignatureStatus::Unsigned,
            (Some(sig), Some(signing_id_bytes)) => {
                // Suite gate: only ML-DSA-44 (suite 100) is accepted.
                if sig.suite_id != PQC_TRANSPORT_SUITE_ML_DSA_44 {
                    return Err(TrustBundleError::UnsupportedSignatureSuite {
                        signing_key_id: sig.signing_key_id.clone(),
                        suite_id: sig.suite_id,
                    });
                }
                // Look up the configured signing key by id.
                let key = signing_keys.lookup(&signing_id_bytes).ok_or_else(|| {
                    TrustBundleError::MissingSigningKey {
                        signing_key_id: sig.signing_key_id.clone(),
                    }
                })?;
                // Cross-check the configured suite against the
                // declared envelope suite (defence in depth — both
                // must currently be ML-DSA-44 / 100).
                if key.suite_id != sig.suite_id {
                    return Err(TrustBundleError::SignatureSuiteMismatch {
                        signing_key_id: sig.signing_key_id.clone(),
                        bundle_suite_id: sig.suite_id,
                        configured_suite_id: key.suite_id,
                    });
                }
                // Decode signature bytes; check length matches suite.
                let sig_bytes = decode_hex_var(&sig.sig_bytes).map_err(|e| {
                    TrustBundleError::MalformedSignatureBytes {
                        signing_key_id: sig.signing_key_id.clone(),
                        reason: e,
                    }
                })?;
                if sig_bytes.len() != ML_DSA_44_SIGNATURE_SIZE {
                    return Err(TrustBundleError::MalformedSignatureBytes {
                        signing_key_id: sig.signing_key_id.clone(),
                        reason: format!(
                            "expected {} bytes, got {}",
                            ML_DSA_44_SIGNATURE_SIZE,
                            sig_bytes.len()
                        ),
                    });
                }
                // Build the canonical signing preimage (domain
                // separator || canonical JSON of bundle with
                // signature stripped). Then verify with ML-DSA-44.
                let preimage = canonical_signing_bytes(&self);
                MlDsa44Backend::verify(&key.pk_bytes, &preimage, &sig_bytes).map_err(
                    |_| TrustBundleError::BadSignature {
                        signing_key_id: sig.signing_key_id.clone(),
                    },
                )?;
                BundleSignatureStatus::Verified {
                    signing_key_id: sig.signing_key_id.clone(),
                }
            }
            // signature.is_some() implies parsed_signing_id.is_some()
            // by construction above; this arm is unreachable but
            // explicit to keep the match exhaustive.
            (Some(sig), None) => {
                return Err(TrustBundleError::MalformedHex(format!(
                    "signing_key_id {} did not parse",
                    sig.signing_key_id
                )));
            }
        };

        // 8. Build the `active_roots` view. A root is "acceptable" iff
        //    its status is Active AND it is within its own validity
        //    window AND it is not on the revocation list.
        let mut active_roots: Vec<PqcTrustedRoot> = Vec::new();
        for (r, id_bytes, pk_bytes) in parsed_roots {
            if !r.status.is_acceptable() {
                continue;
            }
            if validation_time_secs < r.not_before {
                // Fail closed: an Active root that hasn't begun its
                // validity window is a configuration error. We refuse
                // the whole bundle rather than silently dropping the
                // entry — that catches operator typos.
                return Err(TrustBundleError::RootNotYetValid(r.root_id.clone()));
            }
            if validation_time_secs > r.not_after {
                return Err(TrustBundleError::RootExpired(r.root_id.clone()));
            }
            if revoked_root_ids.contains(&id_bytes) {
                continue;
            }
            active_roots.push(PqcTrustedRoot {
                root_key_id: id_bytes,
                suite_id: r.suite_id,
                root_pk: pk_bytes,
            });
        }

        // 9. Deterministic fingerprint. We serialise the bundle (with
        //    the signature stripped, so that resigning a previously-
        //    unsigned bundle does NOT change its fingerprint) using
        //    canonical JSON and hash with SHA3-256. struct field order
        //    is stable across `serde_json::to_vec` invocations.
        let fingerprint = canonical_fingerprint(&self);

        Ok(LoadedTrustBundle {
            bundle: self,
            fingerprint,
            active_roots,
            revoked_root_ids,
            revoked_leaf_fingerprints,
            signature_status,
        })
    }
}

/// Run 051: Canonical signing preimage for an ML-DSA-44 trust-bundle
/// signature.
///
/// ```text
/// preimage = TRUST_BUNDLE_SIGNATURE_DOMAIN_SEPARATOR
///         || serde_json::to_vec(bundle { signature: None })
/// ```
///
/// The domain separator (`QBIND:pqc-trust-bundle-signature:v1`) is
/// distinct from the bundle-fingerprint domain separator
/// (`QBIND:pqc-trust-bundle-fp:v1`), so a fingerprint hash can never
/// collide with a signature preimage.
///
/// The `signature` envelope is stripped so that a bundle's preimage
/// is independent of any signature metadata — adding/removing/
/// replacing the signature does not change what was signed.
pub fn canonical_signing_bytes(bundle: &TrustBundle) -> Vec<u8> {
    let stripped = TrustBundle {
        bundle_version: bundle.bundle_version,
        environment: bundle.environment,
        chain_id: bundle.chain_id.clone(),
        generated_at: bundle.generated_at,
        valid_from: bundle.valid_from,
        valid_until: bundle.valid_until,
        sequence: bundle.sequence,
        roots: bundle.roots.clone(),
        revocations: bundle.revocations.clone(),
        signature: None,
    };
    let json = serde_json::to_vec(&stripped)
        .expect("TrustBundle is pure structs/Vec, serde_json::to_vec cannot fail");
    let mut out =
        Vec::with_capacity(TRUST_BUNDLE_SIGNATURE_DOMAIN_SEPARATOR.len() + json.len());
    out.extend_from_slice(TRUST_BUNDLE_SIGNATURE_DOMAIN_SEPARATOR);
    out.extend_from_slice(&json);
    out
}

/// Run 051: Sign a bundle with an ML-DSA-44 secret key and return a
/// freshly-populated `TrustBundleSignature` envelope. Helper-only;
/// production signing happens out-of-process in a real KMS.
///
/// `signing_key_id` is the canonical 32-byte stable id (typically the
/// SHA3-256 of the signing public key, mirroring
/// `pqc_devnet_helper::derive_root_key_id` but with a different
/// domain separator — see [`derive_signing_key_id`]).
///
/// **DevNet/test fixture only**: this function exists so the helper
/// binary and unit tests can produce signed bundles. Production
/// signing must happen in a real signing service and is out of
/// scope for this layer.
pub fn sign_bundle_devnet_helper(
    bundle: &TrustBundle,
    signing_key_id: [u8; 32],
    signing_sk: &[u8],
) -> Result<TrustBundleSignature, String> {
    let preimage = canonical_signing_bytes(bundle);
    let sig = MlDsa44Backend::sign(signing_sk, &preimage)
        .map_err(|e| format!("ML-DSA-44 trust-bundle sign failed: {:?}", e))?;
    let mut id_hex = String::with_capacity(64);
    for b in &signing_key_id {
        use std::fmt::Write;
        let _ = write!(id_hex, "{:02x}", b);
    }
    let mut sig_hex = String::with_capacity(sig.len() * 2);
    for b in &sig {
        use std::fmt::Write;
        let _ = write!(sig_hex, "{:02x}", b);
    }
    Ok(TrustBundleSignature {
        signing_key_id: id_hex,
        suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
        sig_bytes: sig_hex,
    })
}

/// Run 051: stable id derived from a bundle-signing public key.
///
/// Distinct from `pqc_devnet_helper::derive_root_key_id` only by the
/// SHA3-256 domain-separator string, so a transport root key and a
/// bundle-signing key with the same bytes (which should never happen
/// by policy anyway) still hash to distinct ids — and any code path
/// that confuses the two surfaces the mismatch immediately.
pub fn derive_signing_key_id(signing_pk: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(b"QBIND:pqc-trust-bundle-signing-key-id:v1");
    h.update(signing_pk);
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// SHA3-256 of the canonical JSON encoding of the bundle with the
/// `signature` field replaced by `None`. Deterministic across runs.
pub fn canonical_fingerprint(bundle: &TrustBundle) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let stripped = TrustBundle {
        bundle_version: bundle.bundle_version,
        environment: bundle.environment,
        chain_id: bundle.chain_id.clone(),
        generated_at: bundle.generated_at,
        valid_from: bundle.valid_from,
        valid_until: bundle.valid_until,
        sequence: bundle.sequence,
        roots: bundle.roots.clone(),
        revocations: bundle.revocations.clone(),
        signature: None,
    };
    let bytes = serde_json::to_vec(&stripped)
        .expect("TrustBundle is pure structs/Vec, serde_json::to_vec cannot fail");
    let mut h = Sha3_256::new();
    h.update(b"QBIND:pqc-trust-bundle-fp:v1");
    h.update(&bytes);
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Run 052: domain separator for the canonical leaf-cert fingerprint
/// that the leaf-revocation surface uses to identify a specific
/// validator delegation cert. Distinct from every other SHA3-256
/// domain used by this crate so a leaf-cert fingerprint cannot
/// collide with a bundle fingerprint, signing-key id, transport root
/// id, or any other digest the project produces.
pub const TRUST_BUNDLE_LEAF_FINGERPRINT_DOMAIN_SEPARATOR: &[u8] =
    b"QBIND:pqc-trust-bundle-leaf-fp:v1";

/// Run 052: canonical 32-byte fingerprint of a validator's leaf
/// `NetworkDelegationCert`.
///
/// Defined as
/// `SHA3-256( TRUST_BUNDLE_LEAF_FINGERPRINT_DOMAIN_SEPARATOR || cert.encode() )`
/// where `cert.encode()` is the existing canonical wire encoding via
/// [`qbind_wire::WireEncode`]. The domain-separator string is
/// distinct from every other SHA3-256 domain used by this crate.
///
/// Operators MUST use this fingerprint as the
/// `revocations[i].leaf_cert_fingerprint` value (lowercase 64-char
/// hex) when revoking an individual leaf delegation cert.
///
/// Stability: the inputs to this hash are the exact bytes that a
/// peer would put on the wire, so the fingerprint is invariant
/// under any operator-side reformatting of source files. A cert
/// whose `sig_bytes` is later re-signed (e.g. with a different
/// signing nonce) hashes to a different fingerprint — which is the
/// intended behaviour: leaf-level revocation is per-issued-cert, not
/// per-validator-id.
pub fn cert_leaf_fingerprint(cert: &qbind_wire::net::NetworkDelegationCert) -> [u8; 32] {
    use qbind_wire::io::WireEncode;
    use sha3::{Digest, Sha3_256};
    let mut encoded = Vec::with_capacity(256);
    cert.encode(&mut encoded);
    let mut h = Sha3_256::new();
    h.update(TRUST_BUNDLE_LEAF_FINGERPRINT_DOMAIN_SEPARATOR);
    h.update(&encoded);
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Run 052: hex-encode a 32-byte leaf-cert fingerprint as 64
/// lowercase hex chars (the format that `revocations[i].leaf_cert_fingerprint`
/// is required to use).
pub fn cert_leaf_fingerprint_hex(fp: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in fp {
        use std::fmt::Write;
        let _ = write!(out, "{:02x}", b);
    }
    out
}

// ---------------------------------------------------------------------
// helpers — mirror the hex parsing discipline of `pqc_root_config`.
// ---------------------------------------------------------------------

fn decode_hex_fixed_32(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", s.len()));
    }
    let v = decode_hex_var(s)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

fn decode_hex_var(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd hex length".to_string());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks(2) {
        let hi = nibble(chunk[0])?;
        let lo = nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn parse_bundle_chain_id(s: &str) -> Result<ChainId, String> {
    let hex = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("chain_"))
        .unwrap_or(s);
    if hex.len() != 16 {
        return Err(format!("expected 16 hex chars, got {}", hex.len()));
    }
    let mut value = 0u64;
    for c in hex.bytes() {
        let n = match c {
            b'0'..=b'9' => (c - b'0') as u64,
            b'a'..=b'f' => (10 + c - b'a') as u64,
            _ => return Err(format!("invalid hex char: {:?}", c as char)),
        };
        value = (value << 4) | n;
    }
    Ok(ChainId::new(value))
}

fn nibble(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(10 + c - b'a'),
        // Mirrors `pqc_root_config::nibble`: lowercase-only canonical
        // form to keep the hash stable.
        _ => Err(format!("invalid hex char: {:?}", c as char)),
    }
}

// ---------------------------------------------------------------------
// helper: build a currently-valid DevNet bundle from a freshly minted
// devnet root. Used by `examples/devnet_pqc_trust_bundle_helper.rs` and
// by tests. Lives here so the schema and the helper cannot drift.
// ---------------------------------------------------------------------

/// Helper-only mode selector for fixture bundles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperBundleMode {
    /// Currently valid, no revocations.
    Valid,
    /// Currently valid bundle metadata, but `roots[0].status =
    /// Revoked`. Loading still succeeds (a revoked root that is
    /// explicitly tagged in `status` is excluded from `active_roots`),
    /// but no roots are usable.
    RootStatusRevoked,
    /// Currently valid bundle metadata + an entry in `revocations`
    /// that revokes `roots[0]` defence-in-depth style.
    RootRevocationListed,
    /// Bundle environment intentionally mismatches the loader.
    /// The helper writes a `testnet` bundle; the test loads it with
    /// `expected_env = Devnet`.
    WrongEnvironment,
    /// Bundle is expired (`valid_until = 1`).
    ExpiredBundle,
    /// `roots[0].not_after = 1` (expired root). Loading fails closed.
    ExpiredRoot,
    /// Duplicate `roots[0]` / `roots[1]` (same `root_id`). Loading
    /// fails closed.
    DuplicateRoot,
    /// `roots[0].suite_id = 99` (unsupported). Loading fails closed.
    UnsupportedSuite,
}

/// Build a fixture trust bundle for the given mode. The
/// `(root_id_hex, root_pk_hex)` pair must come from a fresh DevNet
/// root (see `pqc_devnet_helper::mint_devnet_root`).
pub fn build_helper_bundle(
    mode: HelperBundleMode,
    root_id_hex: &str,
    root_pk_hex: &str,
    generated_at: u64,
) -> TrustBundle {
    // For the DuplicateRoot mode we need a second entry; we reuse the
    // same id+pk pair to make the duplicate condition explicit.
    let base_root = TrustBundleRoot {
        root_id: root_id_hex.to_string(),
        suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
        root_pk: root_pk_hex.to_string(),
        status: RootStatus::Active,
        not_before: 0,
        not_after: u64::MAX,
        activation_epoch: None,
        activation_height: None,
    };
    let (environment, valid_from, valid_until, roots, revocations) = match mode {
        HelperBundleMode::Valid => (
            TrustBundleEnvironment::Devnet,
            0u64,
            u64::MAX,
            vec![base_root.clone()],
            vec![],
        ),
        HelperBundleMode::RootStatusRevoked => {
            let mut r = base_root.clone();
            r.status = RootStatus::Revoked;
            (
                TrustBundleEnvironment::Devnet,
                0u64,
                u64::MAX,
                vec![r],
                vec![],
            )
        }
        HelperBundleMode::RootRevocationListed => (
            TrustBundleEnvironment::Devnet,
            0u64,
            u64::MAX,
            vec![base_root.clone()],
            vec![TrustBundleRevocation {
                root_id: root_id_hex.to_string(),
                leaf_cert_fingerprint: None,
                reason: "test-revocation".to_string(),
                effective_from: 0,
            }],
        ),
        HelperBundleMode::WrongEnvironment => (
            // Helper writes a TestNet bundle; the loader is told to
            // expect DevNet, so this produces a `WrongEnvironment`
            // error.
            TrustBundleEnvironment::Testnet,
            0u64,
            u64::MAX,
            vec![base_root.clone()],
            vec![],
        ),
        HelperBundleMode::ExpiredBundle => (
            TrustBundleEnvironment::Devnet,
            0u64,
            1u64,
            vec![base_root.clone()],
            vec![],
        ),
        HelperBundleMode::ExpiredRoot => {
            let mut r = base_root.clone();
            r.not_after = 1;
            (
                TrustBundleEnvironment::Devnet,
                0u64,
                u64::MAX,
                vec![r],
                vec![],
            )
        }
        HelperBundleMode::DuplicateRoot => (
            TrustBundleEnvironment::Devnet,
            0u64,
            u64::MAX,
            vec![base_root.clone(), base_root.clone()],
            vec![],
        ),
        HelperBundleMode::UnsupportedSuite => {
            let mut r = base_root.clone();
            r.suite_id = 99;
            (
                TrustBundleEnvironment::Devnet,
                0u64,
                u64::MAX,
                vec![r],
                vec![],
            )
        }
    };
    TrustBundle {
        bundle_version: TrustBundle::SUPPORTED_SCHEMA_VERSION,
        environment,
        chain_id: None,
        generated_at,
        valid_from,
        valid_until,
        sequence: 1,
        roots,
        revocations,
        signature: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pqc_devnet_helper::mint_devnet_root;

    fn hex_lower(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for x in b {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", x);
        }
        s
    }

    fn fresh_root_pair() -> (String, String) {
        let root = mint_devnet_root().expect("mint root");
        (hex_lower(&root.root_key_id), hex_lower(&root.root_pk))
    }

    #[test]
    fn valid_devnet_unsigned_bundle_loads() {
        let (id, pk) = fresh_root_pair();
        let bundle = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 100);
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let loaded =
            TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Devnet, 200).expect("loads");
        assert_eq!(loaded.active_root_count(), 1);
        assert_eq!(loaded.revoked_root_count(), 0);
        assert_eq!(loaded.environment(), TrustBundleEnvironment::Devnet);
        assert_eq!(loaded.fingerprint_short().len(), 8);
        assert_eq!(loaded.fingerprint_hex().len(), 64);
    }

    #[test]
    fn malformed_bundle_fails_closed() {
        let err = TrustBundle::load_from_bytes(b"{not json", NetworkEnvironment::Devnet, 0)
            .unwrap_err();
        assert!(matches!(err, TrustBundleError::Malformed(_)));
    }

    #[test]
    fn unsupported_schema_version_fails_closed() {
        let (id, pk) = fresh_root_pair();
        let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
        bundle.bundle_version = 7;
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let err =
            TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Devnet, 100).unwrap_err();
        assert!(matches!(err, TrustBundleError::UnsupportedSchemaVersion(7)));
    }

    #[test]
    fn wrong_environment_fails_closed() {
        let (id, pk) = fresh_root_pair();
        let bundle = build_helper_bundle(HelperBundleMode::WrongEnvironment, &id, &pk, 0);
        let bytes = serde_json::to_vec(&bundle).unwrap();
        // Helper produced a testnet bundle; load with expected = devnet.
        let err =
            TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Devnet, 100).unwrap_err();
        assert!(matches!(err, TrustBundleError::WrongEnvironment { .. }));
    }

    #[test]
    fn matching_chain_id_loads_when_present() {
        let (id, pk) = fresh_root_pair();
        let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
        bundle.chain_id = Some("0x51424e4444455600".to_string());
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let loaded = TrustBundle::load_from_bytes_with_signing_keys_and_chain_id(
            &bytes,
            NetworkEnvironment::Devnet,
            qbind_types::QBIND_DEVNET_CHAIN_ID,
            100,
            &BundleSigningKeySet::empty(),
        )
        .expect("matching chain_id loads");
        assert_eq!(loaded.bundle.chain_id.as_deref(), Some("0x51424e4444455600"));
    }

    #[test]
    fn wrong_chain_id_fails_closed_when_present() {
        let (id, pk) = fresh_root_pair();
        let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
        bundle.chain_id = Some("0x51424e4454535400".to_string());
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let err = TrustBundle::load_from_bytes_with_signing_keys_and_chain_id(
            &bytes,
            NetworkEnvironment::Devnet,
            qbind_types::QBIND_DEVNET_CHAIN_ID,
            100,
            &BundleSigningKeySet::empty(),
        )
        .unwrap_err();
        match err {
            TrustBundleError::WrongChainId { expected, found } => {
                assert_eq!(expected, qbind_types::QBIND_DEVNET_CHAIN_ID);
                assert_eq!(found, qbind_types::QBIND_TESTNET_CHAIN_ID);
            }
            other => panic!("expected WrongChainId, got {:?}", other),
        }
    }

    #[test]
    fn malformed_chain_id_fails_closed_when_present() {
        let (id, pk) = fresh_root_pair();
        let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
        bundle.chain_id = Some("0x51424g4444455600".to_string());
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let err =
            TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Devnet, 100).unwrap_err();
        assert!(matches!(err, TrustBundleError::InvalidChainIdFormat(_)));
    }

    #[test]
    fn unsigned_bundle_rejected_on_testnet() {
        let (id, pk) = fresh_root_pair();
        let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
        bundle.environment = TrustBundleEnvironment::Testnet;
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let err =
            TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Testnet, 100).unwrap_err();
        assert!(matches!(
            err,
            TrustBundleError::UnsignedBundleNotAllowed(TrustBundleEnvironment::Testnet)
        ));
    }

    #[test]
    fn unsigned_bundle_rejected_on_mainnet() {
        let (id, pk) = fresh_root_pair();
        let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
        bundle.environment = TrustBundleEnvironment::Mainnet;
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let err =
            TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Mainnet, 100).unwrap_err();
        assert!(matches!(
            err,
            TrustBundleError::UnsignedBundleNotAllowed(TrustBundleEnvironment::Mainnet)
        ));
    }

    #[test]
    fn signed_bundle_without_signing_keys_now_fails_missing_key() {
        // Run 051: with the new verify path, a signed bundle on an
        // empty signing-key set is rejected with MissingSigningKey
        // (no longer SignedBundleVerificationNotImplemented).
        let (id, pk) = fresh_root_pair();
        let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
        bundle.signature = Some(TrustBundleSignature {
            signing_key_id:
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
            suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
            sig_bytes: "00".repeat(ML_DSA_44_SIGNATURE_SIZE),
        });
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let err =
            TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Devnet, 100).unwrap_err();
        assert!(matches!(err, TrustBundleError::MissingSigningKey { .. }));
    }

    #[test]
    fn expired_bundle_fails_closed() {
        let (id, pk) = fresh_root_pair();
        let bundle = build_helper_bundle(HelperBundleMode::ExpiredBundle, &id, &pk, 0);
        let bytes = serde_json::to_vec(&bundle).unwrap();
        // valid_until = 1, time = 100 -> expired.
        let err =
            TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Devnet, 100).unwrap_err();
        assert!(matches!(err, TrustBundleError::BundleExpired));
    }

    #[test]
    fn not_yet_valid_bundle_fails_closed() {
        let (id, pk) = fresh_root_pair();
        let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
        bundle.valid_from = 1_000;
        bundle.valid_until = 2_000;
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let err =
            TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Devnet, 100).unwrap_err();
        assert!(matches!(err, TrustBundleError::BundleNotYetValid));
    }

    #[test]
    fn inverted_bundle_window_fails_closed() {
        let (id, pk) = fresh_root_pair();
        let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
        bundle.valid_from = 100;
        bundle.valid_until = 50;
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let err = TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Devnet, 75).unwrap_err();
        assert!(matches!(err, TrustBundleError::InvalidBundleValidityWindow));
    }

    #[test]
    fn expired_root_fails_closed() {
        let (id, pk) = fresh_root_pair();
        let bundle = build_helper_bundle(HelperBundleMode::ExpiredRoot, &id, &pk, 0);
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let err =
            TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Devnet, 100).unwrap_err();
        assert!(matches!(err, TrustBundleError::RootExpired(_)));
    }

    #[test]
    fn not_yet_valid_root_fails_closed() {
        let (id, pk) = fresh_root_pair();
        let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
        bundle.roots[0].not_before = 10_000;
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let err =
            TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Devnet, 100).unwrap_err();
        assert!(matches!(err, TrustBundleError::RootNotYetValid(_)));
    }

    #[test]
    fn inverted_root_window_fails_closed() {
        let (id, pk) = fresh_root_pair();
        let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
        bundle.roots[0].not_before = 200;
        bundle.roots[0].not_after = 100;
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let err =
            TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Devnet, 150).unwrap_err();
        assert!(matches!(err, TrustBundleError::InvalidRootValidityWindow(_)));
    }

    #[test]
    fn duplicate_root_id_fails_closed() {
        let (id, pk) = fresh_root_pair();
        let bundle = build_helper_bundle(HelperBundleMode::DuplicateRoot, &id, &pk, 0);
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let err =
            TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Devnet, 100).unwrap_err();
        assert!(matches!(err, TrustBundleError::DuplicateRootId(_)));
    }

    #[test]
    fn unsupported_suite_fails_closed() {
        let (id, pk) = fresh_root_pair();
        let bundle = build_helper_bundle(HelperBundleMode::UnsupportedSuite, &id, &pk, 0);
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let err =
            TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Devnet, 100).unwrap_err();
        assert!(matches!(err, TrustBundleError::UnsupportedSuite { .. }));
    }

    #[test]
    fn malformed_root_id_hex_fails_closed() {
        let (_id, pk) = fresh_root_pair();
        let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &"00".repeat(32), &pk, 0);
        bundle.roots[0].root_id =
            "ZZ00000000000000000000000000000000000000000000000000000000000000".to_string();
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let err =
            TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Devnet, 100).unwrap_err();
        assert!(matches!(err, TrustBundleError::MalformedHex(_)));
    }

    #[test]
    fn malformed_root_pk_fails_closed() {
        let (id, _pk) = fresh_root_pair();
        // pk too short.
        let bundle = build_helper_bundle(HelperBundleMode::Valid, &id, "deadbeef", 0);
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let err =
            TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Devnet, 100).unwrap_err();
        assert!(matches!(err, TrustBundleError::MalformedRootPublicKey { .. }));
    }

    #[test]
    fn revoked_status_root_is_excluded_from_active_set() {
        let (id, pk) = fresh_root_pair();
        let bundle = build_helper_bundle(HelperBundleMode::RootStatusRevoked, &id, &pk, 0);
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let loaded =
            TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Devnet, 100).expect("loads");
        assert_eq!(loaded.active_root_count(), 0);
        assert_eq!(loaded.revoked_root_count(), 0); // not on rev list, just status
    }

    #[test]
    fn revocation_list_excludes_root_and_is_lookable() {
        let (id, pk) = fresh_root_pair();
        let bundle = build_helper_bundle(HelperBundleMode::RootRevocationListed, &id, &pk, 0);
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let loaded =
            TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Devnet, 100).expect("loads");
        assert_eq!(loaded.active_root_count(), 0);
        assert_eq!(loaded.revoked_root_count(), 1);
        let id_bytes = decode_hex_fixed_32(&id).unwrap();
        assert!(loaded.is_root_revoked(&id_bytes));
    }

    #[test]
    fn revocation_referencing_unknown_root_fails_closed() {
        let (id, pk) = fresh_root_pair();
        let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
        bundle.revocations.push(TrustBundleRevocation {
            root_id: "ff".repeat(32),
            leaf_cert_fingerprint: None,
            reason: "compromise".to_string(),
            effective_from: 0,
        });
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let err =
            TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Devnet, 100).unwrap_err();
        assert!(matches!(
            err,
            TrustBundleError::RevocationReferencesUnknownRoot(_)
        ));
    }

    #[test]
    fn future_dated_revocation_is_recorded_but_not_yet_active() {
        let (id, pk) = fresh_root_pair();
        let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
        bundle.revocations.push(TrustBundleRevocation {
            root_id: id.clone(),
            leaf_cert_fingerprint: None,
            reason: "scheduled-rotation".to_string(),
            effective_from: 1_000_000,
        });
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let loaded =
            TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Devnet, 100).expect("loads");
        // Root is still active because the revocation has not yet
        // taken effect.
        assert_eq!(loaded.active_root_count(), 1);
        assert_eq!(loaded.revoked_root_count(), 0);
    }

    #[test]
    fn duplicate_revocation_fails_closed() {
        let (id, pk) = fresh_root_pair();
        let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
        bundle.revocations.push(TrustBundleRevocation {
            root_id: id.clone(),
            leaf_cert_fingerprint: None,
            reason: "a".to_string(),
            effective_from: 0,
        });
        bundle.revocations.push(TrustBundleRevocation {
            root_id: id.clone(),
            leaf_cert_fingerprint: None,
            reason: "b".to_string(),
            effective_from: 0,
        });
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let err =
            TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Devnet, 100).unwrap_err();
        assert!(matches!(err, TrustBundleError::DuplicateRevocation(_)));
    }

    // ----- Run 052 leaf-cert revocation surface --------------------------

    /// Build a minimal `NetworkDelegationCert` whose canonical wire
    /// encoding is deterministic. The exact field values do not
    /// matter for the fingerprint-shape tests below; the fields are
    /// chosen to be non-zero so that a zero-cert and this cert do
    /// NOT collide.
    fn build_fixture_cert(validator_byte: u8) -> qbind_wire::net::NetworkDelegationCert {
        qbind_wire::net::NetworkDelegationCert {
            version: 1,
            validator_id: [validator_byte; 32],
            root_key_id: [0x11; 32],
            leaf_kem_suite_id: 1,
            leaf_kem_pk: vec![0x22; 32],
            not_before: 1_000,
            not_after: 2_000,
            ext_bytes: vec![],
            sig_suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
            sig_bytes: vec![0x33; 64],
        }
    }

    #[test]
    fn cert_leaf_fingerprint_is_deterministic_and_distinct() {
        let cert_a = build_fixture_cert(0xAA);
        let cert_b = build_fixture_cert(0xAA);
        let cert_c = build_fixture_cert(0xBB);
        let fp_a1 = cert_leaf_fingerprint(&cert_a);
        let fp_a2 = cert_leaf_fingerprint(&cert_b);
        let fp_c = cert_leaf_fingerprint(&cert_c);
        // Same content -> same fingerprint.
        assert_eq!(fp_a1, fp_a2);
        // Different content -> different fingerprint.
        assert_ne!(fp_a1, fp_c);
        // Hex helper round-trips the byte length.
        assert_eq!(cert_leaf_fingerprint_hex(&fp_a1).len(), 64);
    }

    #[test]
    fn cert_leaf_fingerprint_domain_separator_is_distinct() {
        // The leaf-cert fingerprint domain separator must not equal
        // the bundle fingerprint or signature domain separators. This
        // is what makes leaf-cert fingerprints structurally
        // impossible to confuse with any other digest in the project.
        assert_ne!(
            TRUST_BUNDLE_LEAF_FINGERPRINT_DOMAIN_SEPARATOR,
            TRUST_BUNDLE_SIGNATURE_DOMAIN_SEPARATOR
        );
        assert_ne!(
            TRUST_BUNDLE_LEAF_FINGERPRINT_DOMAIN_SEPARATOR,
            b"QBIND:pqc-trust-bundle-fp:v1".as_slice()
        );
        assert_ne!(
            TRUST_BUNDLE_LEAF_FINGERPRINT_DOMAIN_SEPARATOR,
            b"QBIND:pqc-trust-bundle-signing-key-id:v1".as_slice()
        );
    }

    #[test]
    fn revoked_leaf_fingerprint_is_surfaced_for_lookup() {
        let (id, pk) = fresh_root_pair();
        let cert = build_fixture_cert(0xCC);
        let fp = cert_leaf_fingerprint(&cert);
        let fp_hex = cert_leaf_fingerprint_hex(&fp);
        let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
        bundle.revocations.push(TrustBundleRevocation {
            root_id: id.clone(),
            leaf_cert_fingerprint: Some(fp_hex.clone()),
            reason: "leaf-compromise".to_string(),
            effective_from: 0,
        });
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let loaded =
            TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Devnet, 100).expect("loads");
        // Root is still active (root-level revocation is a separate
        // axis); only the specific leaf is revoked.
        assert_eq!(loaded.active_root_count(), 1);
        assert!(!loaded.is_root_revoked(&decode_hex_fixed_32(&id).unwrap()));
        // Leaf revocation is surfaced.
        assert_eq!(loaded.revoked_leaf_fingerprint_count(), 1);
        assert!(loaded.is_leaf_revoked(&fp));
        // An unrelated cert is NOT revoked.
        let other_fp = cert_leaf_fingerprint(&build_fixture_cert(0xDD));
        assert!(!loaded.is_leaf_revoked(&other_fp));
    }

    #[test]
    fn future_dated_leaf_revocation_is_not_yet_active() {
        let (id, pk) = fresh_root_pair();
        let cert = build_fixture_cert(0xEE);
        let fp = cert_leaf_fingerprint(&cert);
        let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
        bundle.revocations.push(TrustBundleRevocation {
            root_id: id.clone(),
            leaf_cert_fingerprint: Some(cert_leaf_fingerprint_hex(&fp)),
            reason: "scheduled-leaf-rotation".to_string(),
            effective_from: 1_000_000,
        });
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let loaded =
            TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Devnet, 100).expect("loads");
        // Leaf revocation recorded but not yet effective.
        assert_eq!(loaded.revoked_leaf_fingerprint_count(), 0);
        assert!(!loaded.is_leaf_revoked(&fp));
    }

    #[test]
    fn malformed_leaf_fingerprint_fails_closed() {
        let (id, pk) = fresh_root_pair();
        let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
        bundle.revocations.push(TrustBundleRevocation {
            root_id: id.clone(),
            // Wrong length AND illegal char — exercise the parser.
            leaf_cert_fingerprint: Some("ZZ".to_string()),
            reason: "leaf-compromise".to_string(),
            effective_from: 0,
        });
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let err =
            TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Devnet, 100).unwrap_err();
        assert!(matches!(
            err,
            TrustBundleError::MalformedLeafFingerprint { .. }
        ));
    }

    #[test]
    fn leaf_revocation_preserves_root_level_revocation_axis() {
        // Both axes coexist: a bundle can carry a root-level revocation
        // for one root AND a leaf-level revocation under a different
        // root in the same revocations[] list, and BOTH surfaces are
        // populated independently.
        let (id1, pk1) = fresh_root_pair();
        let (id2, pk2) = fresh_root_pair();
        let cert = build_fixture_cert(0xFE);
        let fp = cert_leaf_fingerprint(&cert);
        let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id1, &pk1, 0);
        // Add a second root so we can revoke one root + revoke a leaf
        // under the other root.
        bundle.roots.push(TrustBundleRoot {
            root_id: id2.clone(),
            suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
            root_pk: pk2,
            status: RootStatus::Active,
            not_before: 0,
            not_after: u64::MAX,
            activation_epoch: None,
            activation_height: None,
        });
        // Root-level revocation on root #1.
        bundle.revocations.push(TrustBundleRevocation {
            root_id: id1.clone(),
            leaf_cert_fingerprint: None,
            reason: "root-compromise".to_string(),
            effective_from: 0,
        });
        // Leaf-level revocation under root #2.
        bundle.revocations.push(TrustBundleRevocation {
            root_id: id2.clone(),
            leaf_cert_fingerprint: Some(cert_leaf_fingerprint_hex(&fp)),
            reason: "leaf-compromise".to_string(),
            effective_from: 0,
        });
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let loaded =
            TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Devnet, 100).expect("loads");
        // Root #1 revoked; root #2 still active.
        assert_eq!(loaded.active_root_count(), 1);
        assert_eq!(loaded.revoked_root_count(), 1);
        assert!(loaded.is_root_revoked(&decode_hex_fixed_32(&id1).unwrap()));
        assert!(!loaded.is_root_revoked(&decode_hex_fixed_32(&id2).unwrap()));
        // Leaf revocation surfaced.
        assert_eq!(loaded.revoked_leaf_fingerprint_count(), 1);
        assert!(loaded.is_leaf_revoked(&fp));
    }

    #[test]
    fn unsigned_devnet_bundle_with_leaf_revocation_loads_clean() {
        // Regression guard: leaf-revocation parsing must NOT regress
        // the Run 050 unsigned-DevNet path. A bundle with a single
        // valid leaf-revocation still loads, the signature_status is
        // still Unsigned, and the fingerprint is stable.
        let (id, pk) = fresh_root_pair();
        let cert = build_fixture_cert(0x77);
        let fp = cert_leaf_fingerprint(&cert);
        let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
        bundle.revocations.push(TrustBundleRevocation {
            root_id: id.clone(),
            leaf_cert_fingerprint: Some(cert_leaf_fingerprint_hex(&fp)),
            reason: "leaf-compromise".to_string(),
            effective_from: 0,
        });
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let loaded =
            TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Devnet, 100).expect("loads");
        assert!(matches!(
            loaded.signature_status,
            BundleSignatureStatus::Unsigned
        ));
        assert_eq!(loaded.revoked_leaf_fingerprint_count(), 1);
    }

    #[test]
    fn canonical_fingerprint_is_deterministic() {
        let (id, pk) = fresh_root_pair();
        let bundle_a = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
        let bundle_b = bundle_a.clone();
        let fp_a = canonical_fingerprint(&bundle_a);
        let fp_b = canonical_fingerprint(&bundle_b);
        assert_eq!(fp_a, fp_b);
    }

    #[test]
    fn canonical_fingerprint_strips_signature() {
        let (id, pk) = fresh_root_pair();
        let bundle_a = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
        let mut bundle_b = bundle_a.clone();
        bundle_b.signature = Some(TrustBundleSignature {
            signing_key_id: "ee".repeat(32),
            suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
            sig_bytes: "deadbeef".to_string(),
        });
        let fp_a = canonical_fingerprint(&bundle_a);
        let fp_b = canonical_fingerprint(&bundle_b);
        assert_eq!(
            fp_a, fp_b,
            "fingerprint must be over the bundle content only, not the signature envelope"
        );
    }

    #[test]
    fn canonical_fingerprint_changes_with_root_content() {
        let (id, pk) = fresh_root_pair();
        let bundle_a = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
        let mut bundle_b = bundle_a.clone();
        bundle_b.roots[0].status = RootStatus::Retired;
        assert_ne!(
            canonical_fingerprint(&bundle_a),
            canonical_fingerprint(&bundle_b)
        );
    }

    #[test]
    fn metric_codes_are_stable() {
        assert_eq!(TrustBundleEnvironment::Devnet.metric_code(), 0);
        assert_eq!(TrustBundleEnvironment::Testnet.metric_code(), 1);
        assert_eq!(TrustBundleEnvironment::Mainnet.metric_code(), 2);
    }

    #[test]
    fn loaded_bundle_active_roots_have_canonical_id_bytes() {
        let (id, pk) = fresh_root_pair();
        let bundle = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let loaded =
            TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Devnet, 100).expect("loads");
        let id_bytes = decode_hex_fixed_32(&id).unwrap();
        assert_eq!(loaded.active_roots[0].root_key_id, id_bytes);
        assert_eq!(loaded.active_roots[0].suite_id, PQC_TRANSPORT_SUITE_ML_DSA_44);
        assert_eq!(loaded.active_roots[0].root_pk.len(), ML_DSA_44_PUBLIC_KEY_SIZE);
    }

    // ================================================================
    // Run 051: bundle-signing key parser and signed-bundle verification.
    // ================================================================

    fn fresh_signing_keypair() -> (Vec<u8>, Vec<u8>, [u8; 32]) {
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen");
        let id = derive_signing_key_id(&pk);
        (pk, sk, id)
    }

    fn signing_key_spec(id: [u8; 32], pk: &[u8]) -> String {
        format!(
            "{}:{}:{}",
            hex_lower(&id),
            PQC_TRANSPORT_SUITE_ML_DSA_44,
            hex_lower(pk)
        )
    }

    // ---- parser tests ----------------------------------------------

    #[test]
    fn signing_key_spec_parses_valid() {
        let (pk, _sk, id) = fresh_signing_keypair();
        let spec = signing_key_spec(id, &pk);
        let key = parse_bundle_signing_key_spec(&spec).expect("parse");
        assert_eq!(key.key_id_bytes, id);
        assert_eq!(key.suite_id, PQC_TRANSPORT_SUITE_ML_DSA_44);
        assert_eq!(key.pk_bytes, pk);
        assert_eq!(key.key_id_hex().len(), 64);
        assert_eq!(key.key_id_short().len(), 8);
    }

    #[test]
    fn signing_key_spec_rejects_malformed_keyid() {
        let (pk, _sk, _id) = fresh_signing_keypair();
        let spec = format!(
            "ZZ:{}:{}",
            PQC_TRANSPORT_SUITE_ML_DSA_44,
            hex_lower(&pk)
        );
        let err = parse_bundle_signing_key_spec(&spec).unwrap_err();
        assert!(matches!(err, BundleSigningKeySpecError::MalformedHex(_)));
    }

    #[test]
    fn signing_key_spec_rejects_unsupported_suite() {
        let (pk, _sk, id) = fresh_signing_keypair();
        let spec = format!("{}:99:{}", hex_lower(&id), hex_lower(&pk));
        let err = parse_bundle_signing_key_spec(&spec).unwrap_err();
        assert!(matches!(err, BundleSigningKeySpecError::UnsupportedSuite(99)));
    }

    #[test]
    fn signing_key_spec_rejects_wrong_pk_length() {
        let (_pk, _sk, id) = fresh_signing_keypair();
        let spec = format!(
            "{}:{}:deadbeef",
            hex_lower(&id),
            PQC_TRANSPORT_SUITE_ML_DSA_44
        );
        let err = parse_bundle_signing_key_spec(&spec).unwrap_err();
        assert!(matches!(
            err,
            BundleSigningKeySpecError::WrongPublicKeyLength { .. }
        ));
    }

    #[test]
    fn signing_key_spec_rejects_empty_fields() {
        let (pk, _sk, id) = fresh_signing_keypair();
        let spec = format!(":{}:{}", PQC_TRANSPORT_SUITE_ML_DSA_44, hex_lower(&pk));
        assert!(matches!(
            parse_bundle_signing_key_spec(&spec).unwrap_err(),
            BundleSigningKeySpecError::Malformed(_)
        ));
        let spec = format!("{}::{}", hex_lower(&id), hex_lower(&pk));
        assert!(matches!(
            parse_bundle_signing_key_spec(&spec).unwrap_err(),
            BundleSigningKeySpecError::Malformed(_)
        ));
        let spec = format!("{}:{}:", hex_lower(&id), PQC_TRANSPORT_SUITE_ML_DSA_44);
        assert!(matches!(
            parse_bundle_signing_key_spec(&spec).unwrap_err(),
            BundleSigningKeySpecError::Malformed(_)
        ));
    }

    #[test]
    fn signing_key_spec_rejects_trailing_fields() {
        let (pk, _sk, id) = fresh_signing_keypair();
        let spec = format!(
            "{}:{}:{}:extra",
            hex_lower(&id),
            PQC_TRANSPORT_SUITE_ML_DSA_44,
            hex_lower(&pk)
        );
        assert!(matches!(
            parse_bundle_signing_key_spec(&spec).unwrap_err(),
            BundleSigningKeySpecError::Malformed(_)
        ));
    }

    #[test]
    fn signing_key_set_rejects_duplicate_keyid() {
        let (pk, _sk, id) = fresh_signing_keypair();
        let spec = signing_key_spec(id, &pk);
        let err = BundleSigningKeySet::parse_specs(&[spec.clone(), spec]).unwrap_err();
        assert!(matches!(err, BundleSigningKeySpecError::DuplicateKeyId(_)));
    }

    #[test]
    fn signing_key_set_accumulates_distinct_keys() {
        let (pk1, _sk1, id1) = fresh_signing_keypair();
        let (pk2, _sk2, id2) = fresh_signing_keypair();
        let specs = vec![signing_key_spec(id1, &pk1), signing_key_spec(id2, &pk2)];
        let set = BundleSigningKeySet::parse_specs(&specs).expect("parse");
        assert_eq!(set.len(), 2);
        assert!(set.lookup(&id1).is_some());
        assert!(set.lookup(&id2).is_some());
    }

    // ---- canonical signing bytes ----------------------------------

    #[test]
    fn canonical_signing_bytes_includes_domain_separator() {
        let (id, pk) = fresh_root_pair();
        let bundle = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
        let preimage = canonical_signing_bytes(&bundle);
        assert!(preimage.starts_with(TRUST_BUNDLE_SIGNATURE_DOMAIN_SEPARATOR));
        assert_eq!(
            TRUST_BUNDLE_SIGNATURE_DOMAIN_SEPARATOR,
            b"QBIND:pqc-trust-bundle-signature:v1"
        );
    }

    #[test]
    fn canonical_signing_bytes_is_deterministic() {
        let (id, pk) = fresh_root_pair();
        let a = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
        let b = a.clone();
        assert_eq!(canonical_signing_bytes(&a), canonical_signing_bytes(&b));
    }

    #[test]
    fn canonical_signing_bytes_strips_signature() {
        let (id, pk) = fresh_root_pair();
        let a = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
        let mut b = a.clone();
        b.signature = Some(TrustBundleSignature {
            signing_key_id: "aa".repeat(32),
            suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
            sig_bytes: "bb".repeat(ML_DSA_44_SIGNATURE_SIZE),
        });
        assert_eq!(canonical_signing_bytes(&a), canonical_signing_bytes(&b));
    }

    #[test]
    fn canonical_signing_bytes_changes_with_root_field() {
        let (id, pk) = fresh_root_pair();
        let a = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
        let mut b = a.clone();
        b.roots[0].status = RootStatus::Retired;
        assert_ne!(canonical_signing_bytes(&a), canonical_signing_bytes(&b));
    }

    #[test]
    fn canonical_signing_bytes_changes_with_environment() {
        let (id, pk) = fresh_root_pair();
        let a = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
        let mut b = a.clone();
        b.environment = TrustBundleEnvironment::Testnet;
        assert_ne!(canonical_signing_bytes(&a), canonical_signing_bytes(&b));
    }

    #[test]
    fn canonical_signing_bytes_changes_with_sequence() {
        let (id, pk) = fresh_root_pair();
        let a = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
        let mut b = a.clone();
        b.sequence = a.sequence + 1;
        assert_ne!(canonical_signing_bytes(&a), canonical_signing_bytes(&b));
    }

    #[test]
    fn canonical_signing_bytes_changes_with_revocations() {
        let (id, pk) = fresh_root_pair();
        let a = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
        let mut b = a.clone();
        b.revocations.push(TrustBundleRevocation {
            root_id: id.clone(),
            leaf_cert_fingerprint: None,
            reason: "x".to_string(),
            effective_from: 0,
        });
        assert_ne!(canonical_signing_bytes(&a), canonical_signing_bytes(&b));
    }

    #[test]
    fn signing_and_fingerprint_separators_are_distinct() {
        // Defence in depth: a signature preimage MUST NOT start with
        // the fingerprint domain separator.
        assert_ne!(
            TRUST_BUNDLE_SIGNATURE_DOMAIN_SEPARATOR,
            b"QBIND:pqc-trust-bundle-fp:v1"
        );
    }

    // ---- signature verification end-to-end -------------------------

    /// Build a freshly-signed `(bundle, signing_keys, signing_id)` triple
    /// for the given env.
    fn signed_bundle_fixture(
        env: TrustBundleEnvironment,
    ) -> (TrustBundle, BundleSigningKeySet, [u8; 32], Vec<u8>) {
        let (id_hex, pk_hex) = fresh_root_pair();
        let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id_hex, &pk_hex, 0);
        bundle.environment = env;
        let (signing_pk, signing_sk, signing_id) = fresh_signing_keypair();
        let sig = sign_bundle_devnet_helper(&bundle, signing_id, &signing_sk).expect("sign");
        bundle.signature = Some(sig);
        let mut set = BundleSigningKeySet::empty();
        set.push_spec(&signing_key_spec(signing_id, &signing_pk))
            .expect("set");
        (bundle, set, signing_id, signing_sk)
    }

    #[test]
    fn signed_devnet_bundle_verifies() {
        let (bundle, set, _id, _sk) = signed_bundle_fixture(TrustBundleEnvironment::Devnet);
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let loaded = TrustBundle::load_from_bytes_with_signing_keys(
            &bytes,
            NetworkEnvironment::Devnet,
            100,
            &set,
        )
        .expect("verify");
        assert!(loaded.signature_status.is_verified());
        assert_eq!(loaded.active_root_count(), 1);
    }

    #[test]
    fn signed_testnet_bundle_verifies() {
        let (bundle, set, _id, _sk) = signed_bundle_fixture(TrustBundleEnvironment::Testnet);
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let loaded = TrustBundle::load_from_bytes_with_signing_keys(
            &bytes,
            NetworkEnvironment::Testnet,
            100,
            &set,
        )
        .expect("verify");
        assert!(loaded.signature_status.is_verified());
    }

    #[test]
    fn signed_mainnet_bundle_verifies() {
        let (bundle, set, _id, _sk) = signed_bundle_fixture(TrustBundleEnvironment::Mainnet);
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let loaded = TrustBundle::load_from_bytes_with_signing_keys(
            &bytes,
            NetworkEnvironment::Mainnet,
            100,
            &set,
        )
        .expect("verify");
        assert!(loaded.signature_status.is_verified());
    }

    #[test]
    fn tampered_root_after_signing_fails_closed() {
        let (mut bundle, set, _id, _sk) = signed_bundle_fixture(TrustBundleEnvironment::Devnet);
        // Flip one byte in root_pk *after* signing (signature now
        // covers the original bytes).
        let mut new_pk = bundle.roots[0].root_pk.clone();
        // mutate hex char in a safe position
        let mut chars: Vec<char> = new_pk.chars().collect();
        chars[0] = if chars[0] == '0' { '1' } else { '0' };
        new_pk = chars.into_iter().collect();
        bundle.roots[0].root_pk = new_pk;
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let err = TrustBundle::load_from_bytes_with_signing_keys(
            &bytes,
            NetworkEnvironment::Devnet,
            100,
            &set,
        )
        .unwrap_err();
        assert!(matches!(err, TrustBundleError::BadSignature { .. }));
    }

    #[test]
    fn tampered_environment_after_signing_fails_closed() {
        let (mut bundle, set, _id, _sk) = signed_bundle_fixture(TrustBundleEnvironment::Devnet);
        bundle.environment = TrustBundleEnvironment::Testnet;
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let err = TrustBundle::load_from_bytes_with_signing_keys(
            &bytes,
            NetworkEnvironment::Testnet,
            100,
            &set,
        )
        .unwrap_err();
        assert!(matches!(err, TrustBundleError::BadSignature { .. }));
    }

    #[test]
    fn tampered_sequence_after_signing_fails_closed() {
        let (mut bundle, set, _id, _sk) = signed_bundle_fixture(TrustBundleEnvironment::Devnet);
        bundle.sequence += 1;
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let err = TrustBundle::load_from_bytes_with_signing_keys(
            &bytes,
            NetworkEnvironment::Devnet,
            100,
            &set,
        )
        .unwrap_err();
        assert!(matches!(err, TrustBundleError::BadSignature { .. }));
    }

    #[test]
    fn wrong_signing_key_fails_closed() {
        let (bundle, _set, _id, _sk) = signed_bundle_fixture(TrustBundleEnvironment::Devnet);
        // Same id, but different pk bytes — sneak in a confused
        // entry. Forge the spec with the right id but a fresh
        // (unrelated) pk: verification with that pk must fail.
        let signing_id = decode_hex_fixed_32(
            &bundle.signature.as_ref().unwrap().signing_key_id,
        )
        .unwrap();
        let (other_pk, _other_sk) = MlDsa44Backend::generate_keypair().expect("kg");
        let mut set = BundleSigningKeySet::empty();
        set.keys.push(BundleSigningKey {
            key_id_bytes: signing_id,
            suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
            pk_bytes: other_pk,
        });
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let err = TrustBundle::load_from_bytes_with_signing_keys(
            &bytes,
            NetworkEnvironment::Devnet,
            100,
            &set,
        )
        .unwrap_err();
        assert!(matches!(err, TrustBundleError::BadSignature { .. }));
    }

    #[test]
    fn missing_signing_key_fails_closed() {
        let (bundle, _set, _id, _sk) = signed_bundle_fixture(TrustBundleEnvironment::Devnet);
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let err = TrustBundle::load_from_bytes_with_signing_keys(
            &bytes,
            NetworkEnvironment::Devnet,
            100,
            &BundleSigningKeySet::empty(),
        )
        .unwrap_err();
        assert!(matches!(err, TrustBundleError::MissingSigningKey { .. }));
    }

    #[test]
    fn unsupported_signature_suite_fails_closed() {
        let (mut bundle, set, _id, _sk) = signed_bundle_fixture(TrustBundleEnvironment::Devnet);
        bundle.signature.as_mut().unwrap().suite_id = 99;
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let err = TrustBundle::load_from_bytes_with_signing_keys(
            &bytes,
            NetworkEnvironment::Devnet,
            100,
            &set,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            TrustBundleError::UnsupportedSignatureSuite { suite_id: 99, .. }
        ));
    }

    #[test]
    fn malformed_signature_bytes_fails_closed() {
        let (mut bundle, set, _id, _sk) = signed_bundle_fixture(TrustBundleEnvironment::Devnet);
        bundle.signature.as_mut().unwrap().sig_bytes = "00".to_string(); // wrong length
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let err = TrustBundle::load_from_bytes_with_signing_keys(
            &bytes,
            NetworkEnvironment::Devnet,
            100,
            &set,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            TrustBundleError::MalformedSignatureBytes { .. }
        ));
    }

    #[test]
    fn signing_key_id_colliding_with_root_id_fails_closed() {
        // signature.signing_key_id == roots[0].root_id — fail closed
        // even before verification is attempted.
        let (id_hex, pk_hex) = fresh_root_pair();
        let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id_hex, &pk_hex, 0);
        let (signing_pk, signing_sk, _signing_id) = fresh_signing_keypair();
        // Sign with a real key, but then overwrite the signing_key_id
        // to collide with the root id.
        let id_bytes = decode_hex_fixed_32(&id_hex).unwrap();
        let sig = sign_bundle_devnet_helper(&bundle, id_bytes, &signing_sk).expect("sign");
        bundle.signature = Some(sig);
        let mut set = BundleSigningKeySet::empty();
        // Configure that colliding id (operator typo): the validator
        // must still refuse it before reaching the verifier.
        set.keys.push(BundleSigningKey {
            key_id_bytes: id_bytes,
            suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
            pk_bytes: signing_pk,
        });
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let err = TrustBundle::load_from_bytes_with_signing_keys(
            &bytes,
            NetworkEnvironment::Devnet,
            100,
            &set,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            TrustBundleError::SigningKeyCollidesWithRootId(_)
        ));
    }

    #[test]
    fn unsigned_devnet_bundle_loads_signature_status_unsigned() {
        let (id, pk) = fresh_root_pair();
        let bundle = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let loaded =
            TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Devnet, 100).expect("loads");
        assert_eq!(loaded.signature_status, BundleSignatureStatus::Unsigned);
        assert!(!loaded.signature_status.is_verified());
    }

    #[test]
    fn unsigned_testnet_still_refused() {
        let (id, pk) = fresh_root_pair();
        let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
        bundle.environment = TrustBundleEnvironment::Testnet;
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let err = TrustBundle::load_from_bytes_with_signing_keys(
            &bytes,
            NetworkEnvironment::Testnet,
            100,
            &BundleSigningKeySet::empty(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            TrustBundleError::UnsignedBundleNotAllowed(TrustBundleEnvironment::Testnet)
        ));
    }
}