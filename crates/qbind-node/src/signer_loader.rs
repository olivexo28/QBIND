//! Run 032 — production-safe signer loading for `main.rs::run_p2p_node`.
//!
//! # Scope
//!
//! Run 031 left three precise blockers between the binary path and a
//! real `Arc<TimeoutVerificationContext>`:
//!
//! 1. `main.rs::run_p2p_node` did not read `config.signer_keystore_path`
//!    to materialise `Arc<dyn ValidatorSigner>`;
//! 2. `NodeConfig.network.static_peers` carries no per-peer
//!    `(suite_id, pk_bytes)`;
//! 3. production PQC KEMTLS root-key distribution (C4) remains open.
//!
//! Run 032 lands **only** the smallest of those three: the signer
//! half. This module provides the production-safe loader. It reuses
//! the existing keystore primitives (`FsValidatorKeystore`,
//! `EncryptedFsValidatorKeystore`) and signer abstraction
//! (`LocalKeySigner` implementing `ValidatorSigner`); it does NOT
//! invent a new keystore format, does NOT clone or expose private
//! key bytes, does NOT fall back to deterministic / fake / test
//! keys, and does NOT silently activate timeout verification — that
//! is the sole responsibility of [`crate::timeout_verification_bridge`].
//!
//! # Convention
//!
//! Today the binary derives the keystore entry id from the local
//! validator id as `validator-{N}` (matching `qbind-remote-signer`'s
//! example config and existing keystore integration tests). This is
//! a binary-path naming convention, not a protocol change. If a
//! future config field overrides it, this module is the single
//! place to thread it through.
//!
//! # Security
//!
//! - The signing key never leaves the `Arc<ValidatorSigningKey>`
//!   wrapper that owns it; it is never cloned, serialised, or
//!   logged.
//! - The public key is **derived** from the loaded signing key
//!   (using `derive_validator_public_key`) and used only to compute
//!   a short fingerprint suitable for operator logs.
//! - Errors NEVER include key bytes. They include validator id,
//!   suite id, backend kind, the keystore root path (already in
//!   config), and the entry name — all of which are already public
//!   from the operator's own configuration.

use std::path::Path;
use std::sync::Arc;

use qbind_consensus::ids::ValidatorId;
use qbind_crypto::ConsensusSigSuiteId;

use crate::keystore::{
    EncryptedFsValidatorKeystore, FsValidatorKeystore, KeystoreConfig, KeystoreError,
    LocalKeystoreEntryId, ValidatorKeystore,
};
use crate::node_config::{NodeConfig, SignerMode};
use crate::validator_config::{derive_validator_public_key, EXPECTED_SUITE_ID};
use crate::validator_signer::{LocalKeySigner, ValidatorSigner};

/// Backend kind a loaded signer was constructed from.
///
/// Surfaced in startup logs so operators can verify their declared
/// `signer_mode` actually took effect. Run 032 only wires the
/// local-keystore backends (plain + encrypted); the remote and HSM
/// variants stay unchanged in this run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerBackendKind {
    /// Plaintext filesystem keystore (`FsValidatorKeystore`).
    LocalKeystorePlain,
    /// Encrypted filesystem keystore (`EncryptedFsValidatorKeystore`).
    LocalKeystoreEncrypted,
}

impl std::fmt::Display for SignerBackendKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LocalKeystorePlain => write!(f, "local-keystore-plain"),
            Self::LocalKeystoreEncrypted => write!(f, "local-keystore-encrypted"),
        }
    }
}

/// A successfully-loaded local validator signer plus the safe
/// metadata needed for honest startup logs / metrics.
///
/// `signer` is the only consumer of the loaded private key. The
/// other fields are derived metadata: validator id, declared
/// suite, backend kind, and a short non-reversible public-key
/// fingerprint. None of them carry any secret material.
pub struct LoadedValidatorSigner {
    /// Type-erased signer ready to thread into
    /// [`crate::binary_consensus_loop::TimeoutVerificationContext`]
    /// via `TimeoutVerificationBridgeInputs::signer`.
    pub signer: Arc<dyn ValidatorSigner>,
    /// Local validator id this signer was constructed for.
    pub validator_id: ValidatorId,
    /// Declared signature suite (today: `EXPECTED_SUITE_ID` = 100).
    pub suite_id: ConsensusSigSuiteId,
    /// Backend that produced the signer.
    pub backend: SignerBackendKind,
    /// Short, non-reversible fingerprint of the **public** key
    /// (first four hex bytes). Already public from the validator
    /// set; safe to log.
    pub public_key_fingerprint: String,
    /// Raw public-key bytes derived from the loaded signing key.
    ///
    /// This is *public* information (the same bytes that any peer
    /// would see in the validator set) and is exposed so the binary
    /// path can cross-check it against an operator-configured local
    /// validator consensus key (Run 033). It is **not** secret
    /// material and is only used for comparison; it is never logged
    /// in full.
    pub public_key_bytes: Vec<u8>,
}

impl std::fmt::Debug for LoadedValidatorSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The type-erased signer cannot auto-derive Debug; we
        // print only safe metadata. Critically, the inner
        // `Arc<ValidatorSigningKey>` is NEVER reached.
        f.debug_struct("LoadedValidatorSigner")
            .field("validator_id", &self.validator_id)
            .field("suite_id", &self.suite_id)
            .field("backend", &self.backend)
            .field("public_key_fingerprint", &self.public_key_fingerprint)
            .field("signer", &"<Arc<dyn ValidatorSigner>>")
            .finish()
    }
}

/// Reason a signer load attempt did not produce a usable
/// `Arc<dyn ValidatorSigner>`.
///
/// Every variant is precise enough to differentiate "operator did
/// not configure a keystore" from "operator configured a keystore
/// but it could not be loaded". Errors NEVER carry key bytes.
#[derive(Debug)]
pub enum SignerLoadError {
    /// `signer_keystore_path` was not set on the resolved
    /// `NodeConfig`. This is **not** a fatal error by itself; the
    /// caller decides whether to fail closed (under
    /// `--require-timeout-verification`) or continue with
    /// `verification_ctx: None`.
    KeystorePathNotConfigured,
    /// `signer_mode` is one of the non-local-keystore variants
    /// (`RemoteSigner`, `HsmPkcs11`, `LoopbackTesting`). Run 032
    /// only wires local-keystore loading; other backends are
    /// **unchanged** in this run.
    SignerModeNotWiredYet { mode: SignerMode },
    /// `signer_mode == EncryptedFsV1` but no
    /// `EncryptedKeystoreConfig` could be derived from `NodeConfig`.
    /// Today the binary path expects the passphrase environment
    /// variable to be set; this is documented in the run 032
    /// evidence doc.
    EncryptedKeystoreConfigMissing { detail: &'static str },
    /// Keystore file was not found under the configured root.
    /// Carries the entry name (operator-provided, safe to log).
    EntryNotFound { entry: String },
    /// Keystore file failed to parse / decrypt / validate. The
    /// `kind` string is one of: `"parse"`, `"invalid_key"`,
    /// `"config"`, `"io"` — never key bytes.
    KeystoreLoadFailed { kind: &'static str, detail: String },
    /// Public-key derivation from the loaded signing key failed.
    PublicKeyDerivationFailed { detail: String },
    /// Keystore loaded successfully but the declared / derived
    /// suite is not the supported timeout suite. Activating would
    /// silently mask a verification gap.
    UnsupportedSuite {
        validator_id: ValidatorId,
        suite_id: ConsensusSigSuiteId,
    },
}

impl std::fmt::Display for SignerLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeystorePathNotConfigured => write!(
                f,
                "config.signer_keystore_path is not set; no local validator signer was loaded"
            ),
            Self::SignerModeNotWiredYet { mode } => write!(
                f,
                "signer_mode={} is not wired into run_p2p_node by Run 032; \
                 only local-keystore backends load a signer in this run",
                mode
            ),
            Self::EncryptedKeystoreConfigMissing { detail } => write!(
                f,
                "encrypted-fs signer_mode requires encryption config but it could not be \
                 resolved from NodeConfig: {}",
                detail
            ),
            Self::EntryNotFound { entry } => write!(
                f,
                "keystore entry {:?} not found under the configured signer_keystore_path",
                entry
            ),
            Self::KeystoreLoadFailed { kind, detail } => {
                write!(f, "keystore load failed (kind={}): {}", kind, detail)
            }
            Self::PublicKeyDerivationFailed { detail } => write!(
                f,
                "public-key derivation failed for loaded signing key: {}",
                detail
            ),
            Self::UnsupportedSuite {
                validator_id,
                suite_id,
            } => write!(
                f,
                "loaded signer for {:?} declares unsupported suite {:?} (expected {:?})",
                validator_id, suite_id, EXPECTED_SUITE_ID
            ),
        }
    }
}

impl std::error::Error for SignerLoadError {}

impl From<KeystoreError> for SignerLoadError {
    fn from(e: KeystoreError) -> Self {
        match e {
            KeystoreError::NotFound(entry) => SignerLoadError::EntryNotFound { entry },
            KeystoreError::Parse(detail) => SignerLoadError::KeystoreLoadFailed {
                kind: "parse",
                detail,
            },
            KeystoreError::InvalidKey => SignerLoadError::KeystoreLoadFailed {
                kind: "invalid_key",
                detail: "key material did not validate against the keystore's declared suite"
                    .to_string(),
            },
            KeystoreError::Config(detail) => SignerLoadError::KeystoreLoadFailed {
                kind: "config",
                detail,
            },
            KeystoreError::Io(io_err) => SignerLoadError::KeystoreLoadFailed {
                kind: "io",
                detail: format!("{}", io_err),
            },
        }
    }
}

/// Derive the on-disk keystore entry name from the local validator id.
///
/// Convention: `validator-{N}` (with a hyphen — e.g. `validator-0`,
/// `validator-42`). Matches the existing keystore integration tests
/// (`crates/qbind-node/tests/t14[45]_*.rs`) which use entry names
/// such as `"validator-1"`. This is a binary-path naming
/// convention, not a wire / protocol change.
pub fn keystore_entry_for_validator(validator_id: ValidatorId) -> String {
    format!("validator-{}", validator_id.as_u64())
}

/// Produce a short fingerprint suitable for operator logs.
///
/// Mirrors `crate::key_rotation_cli::key_fingerprint` (4-byte hex
/// prefix). Pinned independently here so the loader does not import
/// from a CLI module.
pub fn public_key_fingerprint(pk_bytes: &[u8]) -> String {
    fn hex_byte(b: u8) -> [u8; 2] {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        [HEX[(b >> 4) as usize], HEX[(b & 0x0f) as usize]]
    }
    let take = pk_bytes.len().min(4);
    let mut s = String::with_capacity(take * 2 + 3);
    for b in &pk_bytes[..take] {
        let h = hex_byte(*b);
        s.push(h[0] as char);
        s.push(h[1] as char);
    }
    if pk_bytes.len() > 4 {
        s.push_str("...");
    }
    s
}

/// Load a local validator signer from `NodeConfig`.
///
/// This is the **only** signer-load entry point the binary path is
/// allowed to call. It refuses every honest "no":
///
/// - `signer_keystore_path` unset ⇒
///   [`SignerLoadError::KeystorePathNotConfigured`].
/// - `signer_mode` is `RemoteSigner` / `HsmPkcs11` /
///   `LoopbackTesting` ⇒
///   [`SignerLoadError::SignerModeNotWiredYet`] (Run 032 explicitly
///   leaves those untouched).
/// - keystore file missing / malformed / undecryptable ⇒
///   [`SignerLoadError::EntryNotFound`] /
///   [`SignerLoadError::KeystoreLoadFailed`].
/// - loaded signing key derives a key under a suite other than
///   `EXPECTED_SUITE_ID` ⇒ [`SignerLoadError::UnsupportedSuite`].
///
/// On success returns a [`LoadedValidatorSigner`] whose `signer`
/// field is type-erased to `Arc<dyn ValidatorSigner>` and is the
/// exact value the caller threads into
/// `TimeoutVerificationBridgeInputs::signer`. The private key
/// material lives only inside the `Arc<ValidatorSigningKey>` owned
/// by the inner `LocalKeySigner`.
pub fn load_validator_signer_from_config(
    config: &NodeConfig,
    local_validator_id: ValidatorId,
) -> Result<LoadedValidatorSigner, SignerLoadError> {
    let keystore_root = match config.signer_keystore_path.as_ref() {
        Some(p) => p.clone(),
        None => return Err(SignerLoadError::KeystorePathNotConfigured),
    };

    let backend_kind = match config.signer_mode {
        SignerMode::EncryptedFsV1 => SignerBackendKind::LocalKeystoreEncrypted,
        // Pre-Run-032: a configured keystore_path with default
        // (LoopbackTesting) signer_mode should still load via the
        // plaintext local keystore, which is what the existing
        // T144 integration tests already cover. Honest "no" for
        // RemoteSigner / HsmPkcs11.
        SignerMode::LoopbackTesting => SignerBackendKind::LocalKeystorePlain,
        mode @ (SignerMode::RemoteSigner | SignerMode::HsmPkcs11) => {
            return Err(SignerLoadError::SignerModeNotWiredYet { mode });
        }
    };

    let entry_name = keystore_entry_for_validator(local_validator_id);
    let entry_id = LocalKeystoreEntryId(entry_name.clone());

    let signing_key = match backend_kind {
        SignerBackendKind::LocalKeystorePlain => {
            let ks = FsValidatorKeystore::new(KeystoreConfig {
                root: keystore_root.clone(),
            });
            ks.load_signing_key(&entry_id)?
        }
        SignerBackendKind::LocalKeystoreEncrypted => {
            let enc_config = encrypted_keystore_config_from_node_config(config)?;
            let ks = EncryptedFsValidatorKeystore::new(keystore_root.clone(), enc_config);
            ks.load_signing_key(&entry_id)?
        }
    };

    // Derive the public key from the loaded signing key (this is
    // the same self-check primitive `verify_signing_key_matches_identity`
    // uses, but we only need the derived bytes for the fingerprint —
    // we don't have a configured peer pubkey to compare against in
    // Run 032).
    let (pk, derived_suite) = derive_validator_public_key(&signing_key)
        .map_err(|detail| SignerLoadError::PublicKeyDerivationFailed { detail })?;

    if derived_suite != EXPECTED_SUITE_ID {
        return Err(SignerLoadError::UnsupportedSuite {
            validator_id: local_validator_id,
            suite_id: derived_suite,
        });
    }

    let signer = Arc::new(LocalKeySigner::new(
        local_validator_id,
        EXPECTED_SUITE_ID.as_u16(),
        Arc::new(signing_key),
    )) as Arc<dyn ValidatorSigner>;

    Ok(LoadedValidatorSigner {
        signer,
        validator_id: local_validator_id,
        suite_id: EXPECTED_SUITE_ID,
        backend: backend_kind,
        public_key_fingerprint: public_key_fingerprint(&pk.0),
        public_key_bytes: pk.0,
    })
}

/// Resolve an [`crate::keystore::EncryptedKeystoreConfig`] from the
/// minimal information `NodeConfig` exposes today.
///
/// Run 032 deliberately keeps the wiring to a single, documented
/// pair of environment variables. We do **not** invent a new config
/// surface for AEAD parameters.
fn encrypted_keystore_config_from_node_config(
    _config: &NodeConfig,
) -> Result<crate::keystore::EncryptedKeystoreConfig, SignerLoadError> {
    // The encrypted keystore reads its passphrase from an env var
    // whose name we own. The KDF iteration count matches the
    // existing T153 default.
    let passphrase_env_var = "QBIND_VALIDATOR_KEY_PASSPHRASE".to_string();
    if std::env::var(&passphrase_env_var).is_err() {
        return Err(SignerLoadError::EncryptedKeystoreConfigMissing {
            detail: "QBIND_VALIDATOR_KEY_PASSPHRASE environment variable is not set",
        });
    }
    Ok(crate::keystore::EncryptedKeystoreConfig {
        passphrase_env_var,
        kdf_iterations: 100_000,
    })
}

/// Helper for `Path` debug logs that must not include the file's
/// own contents — only the path itself, which is operator-provided.
pub fn safe_keystore_path_log(p: &Path) -> String {
    p.display().to_string()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::path::PathBuf;

    use qbind_crypto::ml_dsa44::MlDsa44Backend;
    use qbind_crypto::ValidatorSigningKey;

    use crate::node_config::{NodeConfig, SignerMode};

    fn write_plain_keystore_entry(
        root: &Path,
        entry: &str,
        suite_id: u16,
        sk_bytes: &[u8],
    ) -> PathBuf {
        fs::create_dir_all(root).unwrap();
        let path = root.join(format!("{}.json", entry));
        let hex = sk_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        let body = format!(
            "{{\"suite_id\":{},\"private_key_hex\":\"{}\"}}",
            suite_id, hex
        );
        fs::write(&path, body).unwrap();
        path
    }

    fn make_keypair() -> (Vec<u8>, Vec<u8>) {
        MlDsa44Backend::generate_keypair().expect("ml-dsa-44 keygen")
    }

    fn devnet_config_with_keystore(root: PathBuf) -> NodeConfig {
        let mut cfg = NodeConfig::devnet_v0_preset();
        cfg.signer_keystore_path = Some(root);
        // signer_mode stays `LoopbackTesting` (devnet default) ⇒
        // local-keystore-plain backend, matching the existing
        // T144 integration tests.
        cfg
    }

    #[test]
    fn load_signer_succeeds_with_real_pieces() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (_pk, sk) = make_keypair();
        let validator_id = ValidatorId::new(7);
        write_plain_keystore_entry(
            tmp.path(),
            &keystore_entry_for_validator(validator_id),
            100,
            &sk,
        );
        let cfg = devnet_config_with_keystore(tmp.path().to_path_buf());

        let loaded = load_validator_signer_from_config(&cfg, validator_id).expect("signer load");
        assert_eq!(loaded.validator_id, validator_id);
        assert_eq!(loaded.suite_id, EXPECTED_SUITE_ID);
        assert_eq!(loaded.backend, SignerBackendKind::LocalKeystorePlain);
        assert_eq!(*loaded.signer.validator_id(), validator_id);
        assert_eq!(loaded.signer.suite_id(), 100);
        // Fingerprint is a short hex string, NOT the raw public key.
        assert!(loaded.public_key_fingerprint.len() <= 11);
        assert!(loaded
            .public_key_fingerprint
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == '.'));
    }

    #[test]
    fn missing_keystore_path_is_reported_precisely() {
        let mut cfg = NodeConfig::devnet_v0_preset();
        cfg.signer_keystore_path = None;
        let err = load_validator_signer_from_config(&cfg, ValidatorId::new(0))
            .expect_err("missing path must error");
        assert!(matches!(err, SignerLoadError::KeystorePathNotConfigured));
        let msg = format!("{}", err);
        assert!(msg.contains("not set"));
        // No key bytes anywhere.
        assert!(!msg.to_ascii_lowercase().contains("private"));
    }

    #[test]
    fn unreadable_keystore_path_fails_closed() {
        // Configure a path that does not exist on disk: the
        // FsValidatorKeystore translates that to NotFound for the
        // entry it tries to read.
        let cfg = devnet_config_with_keystore(PathBuf::from(
            "/this/path/should/not/exist/qbind-run-032-test",
        ));
        let err = load_validator_signer_from_config(&cfg, ValidatorId::new(0))
            .expect_err("unreadable path must error");
        match err {
            SignerLoadError::EntryNotFound { entry } => {
                assert_eq!(entry, "validator-0");
            }
            other => panic!("expected EntryNotFound, got {:?}", other),
        }
    }

    #[test]
    fn malformed_keystore_fails_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let validator_id = ValidatorId::new(2);
        let path = tmp.path().join(format!(
            "{}.json",
            keystore_entry_for_validator(validator_id)
        ));
        fs::write(&path, "this is not valid json").unwrap();
        let cfg = devnet_config_with_keystore(tmp.path().to_path_buf());
        let err = load_validator_signer_from_config(&cfg, validator_id)
            .expect_err("malformed must error");
        match err {
            SignerLoadError::KeystoreLoadFailed { kind, detail } => {
                assert_eq!(kind, "parse");
                // No key bytes in the detail string.
                assert!(!detail.contains("private_key_hex"));
            }
            other => panic!("expected KeystoreLoadFailed(parse), got {:?}", other),
        }
    }

    #[test]
    fn wrong_suite_in_keystore_fails_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let validator_id = ValidatorId::new(3);
        let (_pk, sk) = make_keypair();
        // Write with suite_id=99 instead of 100; the inner
        // FsValidatorKeystore::load_signing_key rejects this as
        // InvalidKey.
        write_plain_keystore_entry(
            tmp.path(),
            &keystore_entry_for_validator(validator_id),
            99,
            &sk,
        );
        let cfg = devnet_config_with_keystore(tmp.path().to_path_buf());
        let err = load_validator_signer_from_config(&cfg, validator_id)
            .expect_err("wrong suite must error");
        match err {
            SignerLoadError::KeystoreLoadFailed { kind, .. } => {
                assert_eq!(kind, "invalid_key");
            }
            other => panic!("expected invalid_key, got {:?}", other),
        }
    }

    #[test]
    fn errors_never_carry_key_material() {
        // Build every error variant we can synthesise and confirm
        // their Display strings carry no obvious key material.
        let errs: Vec<SignerLoadError> = vec![
            SignerLoadError::KeystorePathNotConfigured,
            SignerLoadError::SignerModeNotWiredYet {
                mode: SignerMode::RemoteSigner,
            },
            SignerLoadError::EncryptedKeystoreConfigMissing {
                detail: "missing passphrase env var",
            },
            SignerLoadError::EntryNotFound {
                entry: "validator-9".to_string(),
            },
            SignerLoadError::KeystoreLoadFailed {
                kind: "parse",
                detail: "expected JSON object".to_string(),
            },
            SignerLoadError::PublicKeyDerivationFailed {
                detail: "deterministic test path".to_string(),
            },
            SignerLoadError::UnsupportedSuite {
                validator_id: ValidatorId::new(1),
                suite_id: ConsensusSigSuiteId::new(99),
            },
        ];
        for err in errs {
            let msg = format!("{}", err);
            let lower = msg.to_ascii_lowercase();
            assert!(!lower.contains("private_key_hex"));
            assert!(!lower.contains("secret"));
            assert!(!lower.contains("private key bytes"));
        }
    }

    #[test]
    fn remote_signer_mode_is_not_wired_in_run_032() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = devnet_config_with_keystore(tmp.path().to_path_buf());
        cfg.signer_mode = SignerMode::RemoteSigner;
        let err = load_validator_signer_from_config(&cfg, ValidatorId::new(0))
            .expect_err("remote mode must error in 032");
        assert!(matches!(
            err,
            SignerLoadError::SignerModeNotWiredYet {
                mode: SignerMode::RemoteSigner
            }
        ));
    }

    #[test]
    fn hsm_signer_mode_is_not_wired_in_run_032() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = devnet_config_with_keystore(tmp.path().to_path_buf());
        cfg.signer_mode = SignerMode::HsmPkcs11;
        let err = load_validator_signer_from_config(&cfg, ValidatorId::new(0))
            .expect_err("hsm mode must error in 032");
        assert!(matches!(
            err,
            SignerLoadError::SignerModeNotWiredYet {
                mode: SignerMode::HsmPkcs11
            }
        ));
    }

    #[test]
    fn loaded_signer_signs_correctly() {
        // End-to-end positive: load, then sign, then verify the
        // signature using the same backend the bridge uses.
        use qbind_crypto::consensus_sig::ConsensusSigVerifier;
        let tmp = tempfile::tempdir().unwrap();
        let validator_id = ValidatorId::new(11);
        let (pk, sk) = make_keypair();
        write_plain_keystore_entry(
            tmp.path(),
            &keystore_entry_for_validator(validator_id),
            100,
            &sk,
        );
        let cfg = devnet_config_with_keystore(tmp.path().to_path_buf());
        let loaded = load_validator_signer_from_config(&cfg, validator_id).unwrap();

        let preimage = b"run 032 test preimage";
        let sig = loaded.signer.sign_proposal(preimage).unwrap();
        let backend = MlDsa44Backend::new();
        backend
            .verify_proposal(1, &pk, preimage, &sig)
            .expect("signature must verify");

        // Confirm the LoadedValidatorSigner's Debug impl does not
        // expose any private key bytes — only safe metadata.
        let dbg = format!("{:?}", loaded);
        assert!(dbg.contains("LoadedValidatorSigner"));
        assert!(dbg.contains("validator_id"));
        assert!(dbg.contains("public_key_fingerprint"));
        assert!(!dbg.contains("private_key"));
        assert!(!dbg.to_ascii_lowercase().contains("secret"));
        // Confirm Debug of LocalKeySigner directly redacts.
        let inner_dbg = format!(
            "{:?}",
            LocalKeySigner::new(validator_id, 100, Arc::new(ValidatorSigningKey::new(sk)),)
        );
        assert!(inner_dbg.contains("<redacted>"));
        assert!(!inner_dbg.contains("private_key"));
    }

    #[test]
    fn entry_name_convention_is_stable() {
        assert_eq!(
            keystore_entry_for_validator(ValidatorId::new(0)),
            "validator-0"
        );
        assert_eq!(
            keystore_entry_for_validator(ValidatorId::new(42)),
            "validator-42"
        );
    }

    #[test]
    fn fingerprint_is_short_and_safe() {
        // Empty / short / long inputs all produce hex-only output.
        assert_eq!(public_key_fingerprint(&[]), "");
        assert_eq!(public_key_fingerprint(&[0xab]), "ab");
        assert_eq!(public_key_fingerprint(&[0xab, 0xcd]), "abcd");
        assert_eq!(
            public_key_fingerprint(&[0xab, 0xcd, 0xef, 0x01, 0x02, 0x03, 0x04]),
            "abcdef01..."
        );
        // Never reveals the tail bytes.
        let fp = public_key_fingerprint(&[0xde, 0xad, 0xbe, 0xef, 0x99, 0x99, 0x99]);
        assert!(!fp.contains("99"));
    }
}
