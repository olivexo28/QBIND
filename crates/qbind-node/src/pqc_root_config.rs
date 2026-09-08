//! Run 037 (C4 piece (c)): production-honest PQC KEMTLS root-key
//! distribution config.
//!
//! This module is the smallest production-honest replacement for B12's
//! deterministic test-grade `TrustedClientRoots` resolver
//! (`TrustedClientRoots::new(|_| Some(vec![0x01u8; 32]))`) and
//! `DummySig` signature suite registered in `make_test_crypto_provider`.
//!
//! It deliberately does NOT introduce a real production CA / OCSP /
//! CRL infrastructure. It lands the smallest config-driven static root
//! distribution shape that:
//!
//! - is opt-in (via [`PqcRootMode::PqcStaticRoot`]);
//! - distributes per-root `(root_key_id, suite_id, root_pk_bytes)`;
//! - is parsed strictly (duplicate IDs / unsupported suites / malformed
//!   public key bytes / missing roots fail closed);
//! - is verified using the existing `MlDsa44Backend` (the same FIPS 204
//!   primitive already used by validator vote / proposal / timeout
//!   signing — no parallel crypto path);
//! - never accepts `DummySig` signatures.
//!
//! The accompanying offline / dev helper that mints real ML-DSA-signed
//! `NetworkDelegationCert`s lives in
//! `crates/qbind-node/examples/devnet_pqc_root_helper.rs` and is
//! explicitly marked DevNet-ephemeral.
//!
//! # Trust boundary
//!
//! - **Production-honest**: roots are configured from explicit, operator-
//!   provided byte material; no fall-through to deterministic stubs.
//! - **Still DevNet-only**: the helper that mints the leaf cert is
//!   offline / dev only. A production CA flow with rotation / revocation
//!   remains out of scope of this run.
//!
//! # Strict scope
//!
//! - PQC-only: only ML-DSA-44 (`suite_id = 100`) is accepted; any other
//!   suite ID is rejected at parse time.
//! - No classical fallback.
//! - No `DummySig` fallback.
//! - No silent downgrade from `PqcStaticRoot` to test-grade in
//!   production-required mode.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use qbind_crypto::{
    KemSuite, MlKem768Backend, KEM_SUITE_ML_KEM_768, ML_DSA_44_PUBLIC_KEY_SIZE,
    ML_KEM_768_PUBLIC_KEY_SIZE, ML_KEM_768_SECRET_KEY_SIZE,
};
use qbind_wire::io::WireDecode;
use qbind_wire::net::NetworkDelegationCert;

/// Canonical signature suite ID for ML-DSA-44 in the PQC static-root
/// transport-identity path. Mirrors `qbind_crypto::SUITE_PQ_RESERVED_1`
/// (`= 100`) but is exposed here as a `u8` to match the
/// `NetworkDelegationCert.sig_suite_id` and `SignatureSuite::suite_id()`
/// shape used by the network layer.
pub const PQC_TRANSPORT_SUITE_ML_DSA_44: u8 = 100;

/// Selected mutual-auth trust-distribution mode.
///
/// The default is [`PqcRootMode::TestGradeDummySig`] to preserve all
/// pre-Run-037 DevNet test-grade behaviour bit-for-bit. Production
/// callers must explicitly opt into [`PqcRootMode::PqcStaticRoot`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PqcRootMode {
    /// Pre-Run-037 B12 wiring: `DummySig` signature suite +
    /// deterministic `TrustedClientRoots`. Test-grade only. Available
    /// only on DevNet and explicitly-marked dev/test paths.
    #[default]
    TestGradeDummySig,

    /// Run-037 production-honest path: real ML-DSA-44 signature suite
    /// registered in the crypto provider, real ML-DSA-signed
    /// `NetworkDelegationCert` on the wire, and the `TrustedClientRoots`
    /// resolver returns operator-configured PQC root public keys (or
    /// fails closed).
    PqcStaticRoot,
}

impl std::fmt::Display for PqcRootMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TestGradeDummySig => f.write_str("test-grade-dummy-sig"),
            Self::PqcStaticRoot => f.write_str("pqc-static-root"),
        }
    }
}

/// Parse a [`PqcRootMode`] from CLI / env var input. Accepted spellings:
/// `test-grade-dummy-sig`, `test-grade`, `dummy`, `pqc-static-root`,
/// `pqc-static`. Returns `None` for any other input — callers fail
/// closed rather than silently downgrading.
pub fn parse_pqc_root_mode(s: &str) -> Option<PqcRootMode> {
    match s.trim().to_ascii_lowercase().as_str() {
        "test-grade-dummy-sig" | "test-grade" | "dummy" | "test" => {
            Some(PqcRootMode::TestGradeDummySig)
        }
        "pqc-static-root" | "pqc-static" | "pqc" | "static-root" => {
            Some(PqcRootMode::PqcStaticRoot)
        }
        _ => None,
    }
}

/// One configured PQC trust root.
///
/// Carries the bytes the listener / dialer needs to authenticate a
/// peer's `NetworkDelegationCert`:
///
/// - `root_key_id`: 32-byte stable identifier embedded in the cert's
///   `root_key_id` field;
/// - `suite_id`: signature suite that produced the root signature
///   (today: ML-DSA-44 / 100);
/// - `root_pk`: raw root public key bytes for verification.
///
/// **Logging discipline**: only `root_key_id` (hex), `suite_id`, and a
/// short fingerprint of `root_pk` may be logged. Never log full root
/// public key bytes (low risk, but kept in line with the wider key-log
/// hygiene rules).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqcTrustedRoot {
    pub root_key_id: [u8; 32],
    pub suite_id: u8,
    pub root_pk: Vec<u8>,
}

impl PqcTrustedRoot {
    /// Short, log-safe fingerprint of the root public key.
    /// Returns the SHA3-256 truncated to 8 hex chars.
    pub fn pk_fingerprint(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(&self.root_pk);
        let digest = h.finalize();
        // First 4 bytes → 8 hex chars.
        let mut out = String::with_capacity(8);
        for b in &digest[..4] {
            use std::fmt::Write;
            let _ = write!(out, "{:02x}", b);
        }
        out
    }

    /// Hex-encoded `root_key_id` (lowercase, 64 chars).
    pub fn root_key_id_hex(&self) -> String {
        let mut out = String::with_capacity(64);
        for b in &self.root_key_id {
            use std::fmt::Write;
            let _ = write!(out, "{:02x}", b);
        }
        out
    }
}

/// Errors returned by the strict PQC root config parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PqcRootConfigError {
    /// Spec did not have the expected `ROOT_KEY_ID_HEX:SUITE:ROOT_PK_HEX`
    /// form.
    InvalidShape(String),
    /// `root_key_id` was not 64 lowercase hex chars.
    InvalidRootKeyId(String),
    /// `suite_id` was not a recognised production-honest PQC suite.
    /// Currently only `100` (ML-DSA-44) is supported. Any other suite
    /// fails closed — no implicit downgrade.
    UnsupportedSuite(String),
    /// `root_pk` was not valid hex / had the wrong length for the
    /// declared suite.
    MalformedPublicKey(String),
    /// Two `--p2p-trusted-root` entries shared the same `root_key_id`.
    /// Fails closed: the operator must resolve which one is canonical.
    DuplicateRootId(String),
    /// `PqcRootMode::PqcStaticRoot` was selected with
    /// `MutualAuthMode::Required` but no `--p2p-trusted-root` entries
    /// were provided. Fails closed: production-honest mode must not
    /// fall back to test-grade roots.
    MissingRootsRequired,
}

impl std::fmt::Display for PqcRootConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidShape(s) => write!(f, "invalid --p2p-trusted-root spec: {}", s),
            Self::InvalidRootKeyId(s) => write!(f, "invalid root_key_id: {}", s),
            Self::UnsupportedSuite(s) => write!(f, "unsupported suite (PQC required): {}", s),
            Self::MalformedPublicKey(s) => write!(f, "malformed root public key: {}", s),
            Self::DuplicateRootId(s) => write!(f, "duplicate root_key_id: {}", s),
            Self::MissingRootsRequired => f.write_str(
                "PqcStaticRoot + MutualAuthMode::Required selected but no roots configured \
                 (production-honest mode must not silently fall back to test-grade roots)",
            ),
        }
    }
}

impl std::error::Error for PqcRootConfigError {}

/// Strictly parse one `ROOT_KEY_ID_HEX:SUITE:ROOT_PK_HEX` spec.
///
/// - `ROOT_KEY_ID_HEX` must be exactly 64 lowercase hex chars (32 bytes).
/// - `SUITE` is decimal `u8`. Currently only `100` (ML-DSA-44) is
///   accepted.
/// - `ROOT_PK_HEX` is lowercase hex with even length. For ML-DSA-44 it
///   must decode to exactly [`ML_DSA_44_PUBLIC_KEY_SIZE`] bytes.
pub fn parse_one_pqc_trusted_root_spec(s: &str) -> Result<PqcTrustedRoot, PqcRootConfigError> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(PqcRootConfigError::InvalidShape(s.to_string()));
    }
    let parts: Vec<&str> = trimmed.splitn(3, ':').collect();
    if parts.len() != 3 {
        return Err(PqcRootConfigError::InvalidShape(s.to_string()));
    }
    let id_hex = parts[0];
    let suite_str = parts[1];
    let pk_hex = parts[2];

    if id_hex.len() != 64 {
        return Err(PqcRootConfigError::InvalidRootKeyId(format!(
            "expected 64 hex chars, got {}",
            id_hex.len()
        )));
    }
    let root_key_id =
        decode_hex_fixed::<32>(id_hex).map_err(|e| PqcRootConfigError::InvalidRootKeyId(e))?;

    let suite_id: u8 = suite_str
        .parse()
        .map_err(|_| PqcRootConfigError::UnsupportedSuite(format!("not a u8: {}", suite_str)))?;
    if suite_id != PQC_TRANSPORT_SUITE_ML_DSA_44 {
        return Err(PqcRootConfigError::UnsupportedSuite(format!(
            "{} (only PQC suite {} = ML-DSA-44 is accepted)",
            suite_id, PQC_TRANSPORT_SUITE_ML_DSA_44
        )));
    }

    if pk_hex.len() % 2 != 0 {
        return Err(PqcRootConfigError::MalformedPublicKey(
            "odd hex length".to_string(),
        ));
    }
    let root_pk = decode_hex_var(pk_hex).map_err(|e| PqcRootConfigError::MalformedPublicKey(e))?;
    if root_pk.len() != ML_DSA_44_PUBLIC_KEY_SIZE {
        return Err(PqcRootConfigError::MalformedPublicKey(format!(
            "expected {} bytes for ML-DSA-44, got {}",
            ML_DSA_44_PUBLIC_KEY_SIZE,
            root_pk.len()
        )));
    }

    Ok(PqcTrustedRoot {
        root_key_id,
        suite_id,
        root_pk,
    })
}

/// Parse a list of `--p2p-trusted-root` specs into a deduplicated
/// trust set.
///
/// Fails closed on:
/// - any malformed spec;
/// - any duplicate `root_key_id` across the list (we refuse to pick a
///   "winner" silently — the operator must fix the config);
/// - empty list when `require_present = true`.
pub fn parse_pqc_trusted_root_specs(
    specs: &[String],
    require_present: bool,
) -> Result<Vec<PqcTrustedRoot>, PqcRootConfigError> {
    if specs.is_empty() && require_present {
        return Err(PqcRootConfigError::MissingRootsRequired);
    }

    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let mut out: Vec<PqcTrustedRoot> = Vec::with_capacity(specs.len());
    for spec in specs {
        let root = parse_one_pqc_trusted_root_spec(spec)?;
        if !seen.insert(root.root_key_id) {
            return Err(PqcRootConfigError::DuplicateRootId(root.root_key_id_hex()));
        }
        out.push(root);
    }
    Ok(out)
}

/// Optional path-based PQC leaf credentials for the local node.
/// Both files must exist and be parseable when
/// [`PqcRootMode::PqcStaticRoot`] + `MutualAuthMode::Required` are
/// selected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqcLeafCredentials {
    /// Encoded `NetworkDelegationCert` bytes (see
    /// `qbind_wire::net::NetworkDelegationCert`).
    pub cert_bytes: Vec<u8>,
    /// Raw KEM secret key bytes corresponding to `cert.leaf_kem_pk`.
    /// Wrapped in `Vec<u8>` here for parser-shape simplicity; the
    /// runtime wrapper [`qbind_net::keys::KemPrivateKey`] takes
    /// ownership and ensures `ZeroizeOnDrop`.
    pub kem_sk_bytes: Vec<u8>,
}

/// File-system shape for `PqcLeafCredentials`. Each path is a separate
/// file: `cert_path` holds the encoded `NetworkDelegationCert`,
/// `kem_sk_path` holds the raw KEM secret key bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqcLeafCredentialPaths {
    pub cert_path: PathBuf,
    pub kem_sk_path: PathBuf,
}

impl PqcLeafCredentialPaths {
    /// Load both files from disk. No private-key bytes are logged on
    /// the success path; on the error path only the file name is
    /// reported.
    pub fn load(&self) -> Result<PqcLeafCredentials, String> {
        let cert_bytes =
            read_file_strict(&self.cert_path).map_err(|e| format!("--p2p-leaf-cert: {}", e))?;
        let kem_sk_bytes = read_file_strict(&self.kem_sk_path)
            .map_err(|e| format!("--p2p-leaf-cert-key: {}", e))?;
        if cert_bytes.is_empty() {
            return Err("--p2p-leaf-cert: file is empty".to_string());
        }
        if kem_sk_bytes.is_empty() {
            return Err("--p2p-leaf-cert-key: file is empty".to_string());
        }
        validate_ml_kem_768_leaf_material(&cert_bytes, &kem_sk_bytes)
            .map_err(|e| format!("--p2p-leaf-cert/--p2p-leaf-cert-key: {}", e))?;
        Ok(PqcLeafCredentials {
            cert_bytes,
            kem_sk_bytes,
        })
    }
}

/// A configured peer leaf certificate used by the `pqc-static-root`
/// binary path to learn the peer's certified ML-KEM-768 public key
/// before the KEMTLS ClientInit is built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqcPeerLeafCert {
    pub validator_index: u64,
    pub cert_bytes: Vec<u8>,
}

/// Parse `VID:PATH` for a peer leaf cert file.
pub fn parse_pqc_peer_leaf_cert_spec(s: &str) -> Result<PqcPeerLeafCert, String> {
    let (vid_s, path_s) = s
        .split_once(':')
        .ok_or_else(|| "expected VID:PATH".to_string())?;
    let validator_index = vid_s
        .parse::<u64>()
        .map_err(|e| format!("invalid validator id {:?}: {}", vid_s, e))?;
    if path_s.is_empty() {
        return Err("empty peer leaf cert path".to_string());
    }
    let cert_bytes = read_file_strict(Path::new(path_s))?;
    if cert_bytes.is_empty() {
        return Err("peer leaf cert file is empty".to_string());
    }
    let cert = decode_network_delegation_cert(&cert_bytes)?;
    validate_ml_kem_768_leaf_cert_shape(&cert)?;
    Ok(PqcPeerLeafCert {
        validator_index,
        cert_bytes,
    })
}

pub fn decode_network_delegation_cert(cert_bytes: &[u8]) -> Result<NetworkDelegationCert, String> {
    let mut slice: &[u8] = cert_bytes;
    NetworkDelegationCert::decode(&mut slice)
        .map_err(|_| "failed to decode NetworkDelegationCert".to_string())
}

pub fn validate_ml_kem_768_leaf_cert_shape(cert: &NetworkDelegationCert) -> Result<(), String> {
    if cert.leaf_kem_suite_id != KEM_SUITE_ML_KEM_768 {
        return Err(format!(
            "unsupported leaf_kem_suite_id {}; expected {} (ML-KEM-768)",
            cert.leaf_kem_suite_id, KEM_SUITE_ML_KEM_768
        ));
    }
    if cert.leaf_kem_pk.len() != ML_KEM_768_PUBLIC_KEY_SIZE {
        return Err(format!(
            "malformed ML-KEM-768 public key: expected {} bytes, got {}",
            ML_KEM_768_PUBLIC_KEY_SIZE,
            cert.leaf_kem_pk.len()
        ));
    }
    Ok(())
}

pub fn validate_ml_kem_768_leaf_material(
    cert_bytes: &[u8],
    kem_sk_bytes: &[u8],
) -> Result<NetworkDelegationCert, String> {
    let cert = decode_network_delegation_cert(cert_bytes)?;
    validate_ml_kem_768_leaf_cert_shape(&cert)?;
    if kem_sk_bytes.len() != ML_KEM_768_SECRET_KEY_SIZE {
        return Err(format!(
            "malformed ML-KEM-768 secret key: expected {} bytes, got {}",
            ML_KEM_768_SECRET_KEY_SIZE,
            kem_sk_bytes.len()
        ));
    }
    let kem = MlKem768Backend::new();
    let (ct, ss_enc) = kem
        .encaps(&cert.leaf_kem_pk)
        .map_err(|_| "ML-KEM-768 public key rejected".to_string())?;
    let ss_dec = kem
        .decaps(kem_sk_bytes, &ct)
        .map_err(|_| "ML-KEM-768 secret key rejected".to_string())?;
    if ss_enc != ss_dec {
        return Err("ML-KEM-768 secret key does not match certified public key".to_string());
    }
    Ok(cert)
}

fn read_file_strict(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| {
        // Intentionally do NOT include path content; just the path
        // string (which is config-supplied) and the OS error kind.
        format!("{}: {}", path.display(), e)
    })
}

/// Top-level PQC root distribution config built from CLI / env.
///
/// This is the production-honest replacement for the deterministic
/// `TrustedClientRoots::new(|_| Some(vec![0x01u8; 32]))` block in
/// `P2pNodeBuilder::create_connection_configs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqcStaticRootConfig {
    pub mode: PqcRootMode,
    pub trusted_roots: Vec<PqcTrustedRoot>,
    /// Optional per-node leaf credentials. May be absent under
    /// `MutualAuthMode::Disabled` or `Optional`. Required under
    /// `MutualAuthMode::Required` + `PqcRootMode::PqcStaticRoot`.
    pub leaf_credentials: Option<PqcLeafCredentials>,
    /// Optional preloaded peer leaf certs, keyed by validator index at
    /// builder time. Required for multi-peer `pqc-static-root` binary
    /// runs because the dialer must know the certified static KEM pk
    /// before it can produce ClientInit.
    pub peer_leaf_certs: Vec<PqcPeerLeafCert>,
}

impl PqcStaticRootConfig {
    /// A test-grade default with no roots, no leaf creds, and the
    /// pre-Run-037 `DummySig` mode selected.
    pub fn test_grade() -> Self {
        Self {
            mode: PqcRootMode::TestGradeDummySig,
            trusted_roots: Vec::new(),
            leaf_credentials: None,
            peer_leaf_certs: Vec::new(),
        }
    }

    /// Look up a configured root public key by `root_key_id`.
    ///
    /// Returns `None` if the id is unknown — the caller MUST fail
    /// closed (`NetError::ClientCertInvalid("untrusted root")` in the
    /// network layer) rather than silently accepting.
    pub fn lookup_root_pk(&self, root_key_id: &[u8; 32]) -> Option<&PqcTrustedRoot> {
        self.trusted_roots
            .iter()
            .find(|r| &r.root_key_id == root_key_id)
    }
}

// ---------- helpers ----------

fn decode_hex_fixed<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let bytes = decode_hex_var(s)?;
    if bytes.len() != N {
        return Err(format!("expected {} bytes, got {}", N, bytes.len()));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
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
        // We deliberately reject uppercase hex to keep the canonical
        // form unambiguous (matches the rest of QBIND's hex parsing
        // discipline, e.g. `--validator-consensus-key`).
        _ => Err(format!("invalid hex char: {:?}", c as char)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qbind_crypto::MlDsa44Backend;

    fn good_id_hex() -> String {
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_string()
    }

    fn good_pk_hex() -> String {
        let (pk, _sk) = MlDsa44Backend::generate_keypair().expect("keygen");
        let mut s = String::with_capacity(pk.len() * 2);
        for b in &pk {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", b);
        }
        s
    }

    #[test]
    fn parse_mode_canonical_and_aliases() {
        assert_eq!(
            parse_pqc_root_mode("test-grade-dummy-sig"),
            Some(PqcRootMode::TestGradeDummySig)
        );
        assert_eq!(
            parse_pqc_root_mode("dummy"),
            Some(PqcRootMode::TestGradeDummySig)
        );
        assert_eq!(
            parse_pqc_root_mode("pqc-static-root"),
            Some(PqcRootMode::PqcStaticRoot)
        );
        assert_eq!(parse_pqc_root_mode("pqc"), Some(PqcRootMode::PqcStaticRoot));
        // Unknown spelling fails closed.
        assert_eq!(parse_pqc_root_mode("classical"), None);
        assert_eq!(parse_pqc_root_mode(""), None);
    }

    #[test]
    fn parse_one_root_ok() {
        let spec = format!("{}:100:{}", good_id_hex(), good_pk_hex());
        let root = parse_one_pqc_trusted_root_spec(&spec).expect("ok");
        assert_eq!(root.suite_id, 100);
        assert_eq!(root.root_pk.len(), ML_DSA_44_PUBLIC_KEY_SIZE);
        assert_eq!(root.root_key_id_hex(), good_id_hex());
        // Fingerprint is 8 hex chars.
        assert_eq!(root.pk_fingerprint().len(), 8);
    }

    #[test]
    fn parse_one_root_rejects_bad_id() {
        // Wrong length.
        let spec = format!("deadbeef:100:{}", good_pk_hex());
        let err = parse_one_pqc_trusted_root_spec(&spec).unwrap_err();
        assert!(matches!(err, PqcRootConfigError::InvalidRootKeyId(_)));
        // Non-hex char.
        let spec = format!(
            "ZZ112233445566778899aabbccddeeff00112233445566778899aabbccddeeff:100:{}",
            good_pk_hex()
        );
        let err = parse_one_pqc_trusted_root_spec(&spec).unwrap_err();
        assert!(matches!(err, PqcRootConfigError::InvalidRootKeyId(_)));
    }

    #[test]
    fn parse_one_root_rejects_unsupported_suite() {
        // Suite 0 (test-grade SHA3) MUST NOT be accepted in
        // production-honest mode.
        let spec = format!("{}:0:{}", good_id_hex(), good_pk_hex());
        let err = parse_one_pqc_trusted_root_spec(&spec).unwrap_err();
        assert!(matches!(err, PqcRootConfigError::UnsupportedSuite(_)));
        // Suite 99 (unknown) is rejected too.
        let spec = format!("{}:99:{}", good_id_hex(), good_pk_hex());
        let err = parse_one_pqc_trusted_root_spec(&spec).unwrap_err();
        assert!(matches!(err, PqcRootConfigError::UnsupportedSuite(_)));
    }

    #[test]
    fn parse_one_root_rejects_malformed_pk() {
        // Wrong length for ML-DSA-44.
        let spec = format!("{}:100:deadbeef", good_id_hex());
        let err = parse_one_pqc_trusted_root_spec(&spec).unwrap_err();
        assert!(matches!(err, PqcRootConfigError::MalformedPublicKey(_)));
        // Odd-length hex.
        let spec = format!("{}:100:abc", good_id_hex());
        let err = parse_one_pqc_trusted_root_spec(&spec).unwrap_err();
        assert!(matches!(err, PqcRootConfigError::MalformedPublicKey(_)));
    }

    #[test]
    fn parse_one_root_rejects_invalid_shape() {
        let err = parse_one_pqc_trusted_root_spec("no-colons-here").unwrap_err();
        assert!(matches!(err, PqcRootConfigError::InvalidShape(_)));
        let err = parse_one_pqc_trusted_root_spec("only:two").unwrap_err();
        assert!(matches!(err, PqcRootConfigError::InvalidShape(_)));
    }

    #[test]
    fn duplicate_root_id_fails_closed() {
        let pk_hex = good_pk_hex();
        let id_hex = good_id_hex();
        let specs = vec![
            format!("{}:100:{}", id_hex, pk_hex),
            format!("{}:100:{}", id_hex, pk_hex),
        ];
        let err = parse_pqc_trusted_root_specs(&specs, true).unwrap_err();
        assert!(matches!(err, PqcRootConfigError::DuplicateRootId(_)));
    }

    #[test]
    fn missing_roots_required_fails_closed() {
        // require_present = true with empty list ⇒ fail closed.
        let err = parse_pqc_trusted_root_specs(&[], true).unwrap_err();
        assert!(matches!(err, PqcRootConfigError::MissingRootsRequired));
        // require_present = false with empty list ⇒ Ok([]).
        let out = parse_pqc_trusted_root_specs(&[], false).expect("ok");
        assert!(out.is_empty());
    }

    #[test]
    fn lookup_root_pk_strict() {
        let pk_hex = good_pk_hex();
        let id_a = good_id_hex();
        let id_b = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100".to_string();
        let specs = vec![
            format!("{}:100:{}", id_a, pk_hex),
            format!("{}:100:{}", id_b, pk_hex),
        ];
        let roots = parse_pqc_trusted_root_specs(&specs, true).expect("ok");
        let cfg = PqcStaticRootConfig {
            mode: PqcRootMode::PqcStaticRoot,
            trusted_roots: roots,
            leaf_credentials: None,
            peer_leaf_certs: Vec::new(),
        };

        // Configured ID ⇒ Some.
        let id_a_bytes = decode_hex_fixed::<32>(&id_a).unwrap();
        assert!(cfg.lookup_root_pk(&id_a_bytes).is_some());

        // Unknown ID ⇒ None (caller must fail closed).
        let unknown = [0u8; 32];
        assert!(cfg.lookup_root_pk(&unknown).is_none());
    }

    #[test]
    fn test_grade_default_has_no_roots() {
        let cfg = PqcStaticRootConfig::test_grade();
        assert_eq!(cfg.mode, PqcRootMode::TestGradeDummySig);
        assert!(cfg.trusted_roots.is_empty());
        assert!(cfg.leaf_credentials.is_none());
    }

    #[test]
    fn root_fingerprint_is_short_and_hex() {
        let spec = format!("{}:100:{}", good_id_hex(), good_pk_hex());
        let root = parse_one_pqc_trusted_root_spec(&spec).unwrap();
        let fp = root.pk_fingerprint();
        assert_eq!(fp.len(), 8);
        for c in fp.chars() {
            assert!(c.is_ascii_hexdigit());
        }
    }

    #[test]
    fn rejects_uppercase_hex_root_key_id() {
        // Canonical lowercase form is enforced (matches the rest of
        // QBIND's hex parsing).
        let spec = format!(
            "AA112233445566778899aabbccddeeff00112233445566778899aabbccddeeff:100:{}",
            good_pk_hex()
        );
        let err = parse_one_pqc_trusted_root_spec(&spec).unwrap_err();
        assert!(matches!(err, PqcRootConfigError::InvalidRootKeyId(_)));
    }

    #[test]
    fn leaf_material_rejects_wrong_size_secret_key() {
        use crate::pqc_devnet_helper::{
            encode_cert, issue_leaf_delegation_cert, mint_devnet_root, LeafCertSpec,
        };

        let root = mint_devnet_root().expect("root");
        let (kem_pk, _kem_sk) = MlKem768Backend::generate_keypair().expect("ml-kem");
        let cert = issue_leaf_delegation_cert(
            &LeafCertSpec {
                validator_id: [1u8; 32],
                root_key_id: root.root_key_id,
                leaf_kem_suite_id: KEM_SUITE_ML_KEM_768,
                leaf_kem_pk: kem_pk,
                not_before: 0,
                not_after: u64::MAX,
                ext_bytes: vec![],
            },
            &root.root_sk,
        )
        .expect("cert");

        let err = validate_ml_kem_768_leaf_material(&encode_cert(&cert), &[0u8; 32]).unwrap_err();
        assert!(err.contains("expected 2400 bytes"));
    }

    #[test]
    fn leaf_material_rejects_wrong_secret_key_for_cert_public_key() {
        use crate::pqc_devnet_helper::{
            encode_cert, issue_leaf_delegation_cert, mint_devnet_root, LeafCertSpec,
        };

        let root = mint_devnet_root().expect("root");
        let (kem_pk, _kem_sk) = MlKem768Backend::generate_keypair().expect("ml-kem");
        let (_other_pk, other_sk) = MlKem768Backend::generate_keypair().expect("other ml-kem");
        let cert = issue_leaf_delegation_cert(
            &LeafCertSpec {
                validator_id: [2u8; 32],
                root_key_id: root.root_key_id,
                leaf_kem_suite_id: KEM_SUITE_ML_KEM_768,
                leaf_kem_pk: kem_pk,
                not_before: 0,
                not_after: u64::MAX,
                ext_bytes: vec![],
            },
            &root.root_sk,
        )
        .expect("cert");

        let err = validate_ml_kem_768_leaf_material(&encode_cert(&cert), &other_sk).unwrap_err();
        assert!(err.contains("does not match"));
    }
}
