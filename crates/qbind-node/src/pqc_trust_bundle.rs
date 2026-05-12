//! Run 050 (C4 piece: PQC transport trust-anchor lifecycle —
//! foundation layer): structured, environment-bound, canonically-hashable
//! PQC trust-anchor bundle.
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
//! # Signature model (Run 050)
//!
//! - **DevNet**: unsigned bundles are accepted (explicitly scoped to
//!   DevNet, mirrors the DevNet ephemeral-root helper that exists
//!   since Run 037).
//! - **TestNet / MainNet**: unsigned bundles are REFUSED at load time.
//!   Signed bundles are also REFUSED at load time *for now* with a
//!   precise error pointing operators at C4 — the signed-bundle
//!   verification flow is not implemented in this layer.
//!
//! This is the documented "Option B + future Option C" boundary in
//! the Run 050 task description: smallest layer that lands real
//! environment binding and root-level revocation enforcement on
//! DevNet today, without claiming TestNet/MainNet readiness.

use std::collections::HashSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use qbind_crypto::ML_DSA_44_PUBLIC_KEY_SIZE;
use qbind_types::NetworkEnvironment;

use crate::pqc_root_config::{PqcTrustedRoot, PQC_TRANSPORT_SUITE_ML_DSA_44};

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
    /// Optional chain-id (hex) when available. Recorded for future
    /// crosscheck against the runtime chain id; NOT enforced today
    /// to keep this layer minimal.
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
    /// The bundle carries a signature but signed-bundle verification
    /// is not implemented in this layer (Run 050 boundary). Recorded
    /// as a remaining C4 piece in `contradiction.md`.
    SignedBundleVerificationNotImplemented,
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
            Self::SignedBundleVerificationNotImplemented => f.write_str(
                "trust bundle carries a signature but signed-bundle verification is not \
                 implemented in this layer (Run 050 boundary). See \
                 docs/whitepaper/contradiction.md C4 (signed root distribution).",
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
}

impl TrustBundle {
    /// Currently supported schema version.
    pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;

    /// Load + validate from a JSON file on disk.
    pub fn load_from_path(
        path: &Path,
        expected_env: NetworkEnvironment,
        validation_time_secs: u64,
    ) -> Result<LoadedTrustBundle, TrustBundleError> {
        let bytes = std::fs::read(path)
            .map_err(|e| TrustBundleError::Io(format!("{}: {}", path.display(), e)))?;
        Self::load_from_bytes(&bytes, expected_env, validation_time_secs)
    }

    /// Load + validate from in-memory bytes. Useful for tests and for
    /// the helper binary.
    pub fn load_from_bytes(
        bytes: &[u8],
        expected_env: NetworkEnvironment,
        validation_time_secs: u64,
    ) -> Result<LoadedTrustBundle, TrustBundleError> {
        let bundle: TrustBundle = serde_json::from_slice(bytes)
            .map_err(|e| TrustBundleError::Malformed(format!("{}", e)))?;
        bundle.validate_at(expected_env, validation_time_secs)
    }

    /// Validate and produce the [`LoadedTrustBundle`] derived data.
    /// Pure: takes no I/O.
    pub fn validate_at(
        self,
        expected_env: NetworkEnvironment,
        validation_time_secs: u64,
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

        // 3. Signature model boundary (Run 050).
        //
        //    DevNet      -> unsigned OK; signed rejected as "not yet
        //                   implemented" so that DevNet test artifacts
        //                   never accidentally exercise an unverified
        //                   signature path and mask a future regression.
        //    TestNet/MainNet -> unsigned rejected; signed rejected as
        //                   "not yet implemented" (NO silent fall-through
        //                   to "accept" — the operator must wait for the
        //                   signed-bundle verification piece).
        match (&self.signature, self.environment) {
            (None, TrustBundleEnvironment::Devnet) => {
                // OK — DevNet unsigned scaffolding.
            }
            (None, env @ (TrustBundleEnvironment::Testnet | TrustBundleEnvironment::Mainnet)) => {
                return Err(TrustBundleError::UnsignedBundleNotAllowed(env));
            }
            (Some(_), _) => {
                return Err(TrustBundleError::SignedBundleVerificationNotImplemented);
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
        //    known root id; duplicates fail closed.
        let mut revoked_root_ids: HashSet<[u8; 32]> = HashSet::new();
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
            if !revoked_root_ids.insert(id_bytes) {
                return Err(TrustBundleError::DuplicateRevocation(rev.root_id.clone()));
            }
            // `effective_from` in the future: still record the
            // revocation, but it does not yet exclude the root. That
            // matches the task definition of `effective_from` as
            // "the time at which this revocation activates".
            if rev.effective_from > validation_time_secs {
                revoked_root_ids.remove(&id_bytes);
            }
        }

        // 7. Trust-separation: signing_key_id MUST NOT collide with
        //    any root_id. (We already validated `signature == Some(_)`
        //    is rejected above, but recheck defensively in case the
        //    signature path is enabled in a future patch — fail
        //    closed here too.)
        if let Some(sig) = &self.signature {
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
        }

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
        })
    }
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
    fn signed_bundle_not_yet_supported_anywhere() {
        let (id, pk) = fresh_root_pair();
        let mut bundle = build_helper_bundle(HelperBundleMode::Valid, &id, &pk, 0);
        bundle.signature = Some(TrustBundleSignature {
            signing_key_id:
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
            suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
            sig_bytes: "00".to_string(),
        });
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let err =
            TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Devnet, 100).unwrap_err();
        assert!(matches!(
            err,
            TrustBundleError::SignedBundleVerificationNotImplemented
        ));
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
}