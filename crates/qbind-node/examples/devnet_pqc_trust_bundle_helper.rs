//! Run 050/051: DevNet-only helper that mints a real ML-DSA-44-signed
//! PQC trust root, generates per-validator leaf certs (delegating to
//! the existing Run 037 `devnet_pqc_root_helper` shape), AND emits a
//! Run 050/051 PQC trust-anchor bundle (`trust-bundle.json`) covering
//! the requested fixture mode — including signed-bundle fixtures for
//! Run 051 (DevNet/TestNet/MainNet signed bundles, tampered, wrong
//! signing key, unsupported suite, signing-key/root-id collision,
//! malformed signature bytes, and unsigned TestNet/MainNet).
//!
//! Usage:
//!   cargo run -p qbind-node --example devnet_pqc_trust_bundle_helper -- \
//!     <outdir> <num_validators> [bundle_mode]
//!
//! `bundle_mode` (optional, defaults to `valid`):
//!   Run 050 fixtures (unsigned):
//!   - `valid`              — currently-valid DevNet unsigned bundle.
//!   - `wrong-environment`  — TestNet bundle (DevNet loader rejects).
//!   - `expired-bundle`     — `valid_until=1` (loader rejects as expired).
//!   - `expired-root`       — root `not_after=1` (loader rejects).
//!   - `root-revocation-listed` — root present in `revocations[]`
//!                                (loader accepts bundle but root is
//!                                excluded from the active set).
//!   - `root-status-revoked` — `roots[0].status = "revoked"`.
//!   - `duplicate-root`     — two `roots[]` entries with same id.
//!   - `unsupported-suite`  — `roots[0].suite_id = 99`.
//!
//!   Run 051 fixtures (signed-bundle):
//!   - `signed-devnet`      — valid signed DevNet bundle.
//!   - `signed-testnet`     — valid signed TestNet bundle.
//!   - `signed-mainnet`     — valid signed MainNet bundle.
//!   - `signed-tampered`    — valid signature, then root mutated.
//!   - `signed-wrong-key`   — signed by a different ML-DSA-44 key
//!                            than the one the helper publishes for
//!                            the `--p2p-trust-bundle-signing-key`
//!                            flag (verification will fail closed).
//!   - `signed-unsupported-suite` — signature envelope sets
//!                            `suite_id = 99` post-signing.
//!   - `signed-malformed`   — signature envelope's `sig_bytes` is
//!                            truncated to 1 byte after signing.
//!   - `signed-key-root-collision` — signing_key_id is overwritten
//!                            to collide with roots[0].root_id.
//!   - `unsigned-testnet`   — unsigned bundle declared `testnet`
//!                            (TestNet/MainNet loader rejects).
//!   - `unsigned-mainnet`   — unsigned bundle declared `mainnet`.
//!
//!   Run 059 fixtures (signed-bundle, MainNet env, for MainNet
//!   release-binary negative smokes):
//!   - `signed-mainnet-tampered`  — MainNet-env signed bundle, then
//!                                  `roots[0].not_after` mutated
//!                                  after signing (signature no
//!                                  longer verifies). Same tamper
//!                                  semantics as `signed-tampered`,
//!                                  emitted with `environment=mainnet`.
//!   - `signed-mainnet-wrong-key` — MainNet-env bundle signed by
//!                                  one ML-DSA-44 keypair, but the
//!                                  helper publishes an unrelated
//!                                  ML-DSA-44 keypair as the
//!                                  `--p2p-trust-bundle-signing-key`
//!                                  the operator should use, so
//!                                  verification fails closed. Same
//!                                  semantics as `signed-wrong-key`,
//!                                  emitted with `environment=mainnet`.
//!
//!   Run 054 fixtures (signed-bundle + active leaf revocation, DevNet):
//!   - `signed-devnet-revoked-v0`      — signed DevNet bundle that
//!                                       revokes the v0 validator
//!                                       leaf cert fingerprint.
//!   - `signed-devnet-revoked-v1`      — signed DevNet bundle that
//!                                       revokes the v1 validator
//!                                       leaf cert fingerprint.
//!   - `signed-devnet-revoked-unknown` — signed DevNet bundle that
//!                                       revokes a synthetic
//!                                       all-zeros leaf fingerprint
//!                                       which no real validator
//!                                       leaf cert can produce.
//!
//!   Run 062 fixtures (signed-bundle + per-entry revocation activation
//!   gate, DevNet):
//!   - `signed-devnet-leaf-revocation-pending-v0` — signed DevNet
//!                                       bundle that revokes the v0
//!                                       validator leaf cert with
//!                                       `activation_height = u64::MAX`
//!                                       (revocation is PENDING at
//!                                       startup — does NOT reject
//!                                       the v0 leaf yet).
//!   - `signed-devnet-leaf-revocation-active-v0` — signed DevNet
//!                                       bundle that revokes the v0
//!                                       validator leaf cert with
//!                                       `activation_height = 0`
//!                                       (revocation is ACTIVE at
//!                                       startup — same enforcement
//!                                       as the existing Run 054
//!                                       `signed-devnet-revoked-v0`,
//!                                       but the entry now carries an
//!                                       explicit height gate covered
//!                                       by the bundle signature).
//!   - `signed-devnet-root-revocation-pending` — signed DevNet bundle
//!                                       with a root-scope revocation
//!                                       carrying
//!                                       `activation_height = u64::MAX`
//!                                       (root remains in active_roots
//!                                       at startup; revocation
//!                                       PENDING).
//!   - `signed-devnet-root-revocation-active` — signed DevNet bundle
//!                                       with a root-scope revocation
//!                                       carrying
//!                                       `activation_height = 0`
//!                                       (root excluded from
//!                                       active_roots immediately;
//!                                       legacy Run 050 behaviour).
//!
//!   Run 063 fixtures (signed-bundle + local revoked-issuer-root
//!   startup self-check, DevNet):
//!   - `signed-devnet-issuer-root-revocation-active-v0` — signed
//!                                       DevNet bundle that mints a
//!                                       SECOND fresh DevNet root and
//!                                       appends it to `roots[]`
//!                                       BEFORE signing, then root-
//!                                       revokes `roots[0]` (the
//!                                       v0..vN leaf-issuing root)
//!                                       with `activation_height =
//!                                       None` (immediately active).
//!                                       With a second still-active
//!                                       root in place, the Run 050
//!                                       `trusted_roots.is_empty()`
//!                                       FATAL does NOT fire — the
//!                                       Run 063 startup self-check
//!                                       fires on a node pointed at
//!                                       `v0.cert.bin` because the
//!                                       cert's issuing root is on
//!                                       the active `revoked_root_ids`
//!                                       set.
//!   - `signed-devnet-issuer-root-revocation-pending-v0` — same
//!                                       two-root shape as
//!                                       `*-active-v0` but with
//!                                       `activation_height =
//!                                       u64::MAX`. The revocation
//!                                       stays PENDING under the
//!                                       binary's loader, so neither
//!                                       Run 050 nor Run 063 fires —
//!                                       the node starts cleanly
//!                                       even though the bundle
//!                                       DECLARES the v0 issuer's
//!                                       root revoked.
//!
//! Optional 4th positional argument: `[sequence_override]`
//!   Decimal `u64`. If supplied, the bundle's `sequence` field is set
//!   to this value BEFORE signing (for signed modes) and before the
//!   canonical fingerprint is computed. Defaults to whatever
//!   `build_helper_bundle` emits (currently `1`). This is an
//!   evidence-tooling knob used by Run 056 to mint
//!   `sequence=1`/`sequence=2`/equivocation fixtures on the same
//!   DevNet trust domain shape; it does NOT change signing semantics
//!   (the new sequence is part of the signed preimage exactly as
//!   `build_helper_bundle` would have produced).
//!
//! Optional 5th positional argument: `[activation_height_override]`
//!   Decimal `u64` or the literal string `none`. If supplied as a
//!   decimal `u64`, the bundle's bundle-level `activation_height`
//!   field is set to this value BEFORE signing and before the
//!   canonical fingerprint is computed. The literal string `none`
//!   forces `activation_height = null` explicitly (equivalent to
//!   omitting this argument when no later positional argument is
//!   needed). Defaults to `None` (no bundle-level activation gate).
//!   This is an evidence-tooling knob used by Run 057 to mint
//!   "future-activation" fixtures on the same DevNet trust domain
//!   shape and extended by Run 067 to allow minting a MainNet
//!   signed bundle WITHOUT a bundle-level `activation_height` while
//!   still pinning a non-default `chain_id_override` (the Run 065
//!   per-environment minimum activation-margin policy rejects any
//!   in-window positive `activation_height` on a fresh MainNet data
//!   dir, so the positive Run 067 smoke needs `activation_height =
//!   None` paired with an explicit MainNet `chain_id`). It does NOT
//!   change signing semantics (the field is part of the signed
//!   preimage and canonical fingerprint, as
//!   `pqc_trust_bundle::canonical_signing_bytes` /
//!   `canonical_fingerprint` already include it).
//!
//! Optional 6th positional argument: `[chain_id_override]`
//!   Bundle `chain_id` declaration written into the trust bundle
//!   BEFORE signing and before the canonical fingerprint is computed.
//!   Accepts the same wire-format the loader accepts:
//!   16 lowercase hex chars optionally prefixed with `0x` or
//!   `chain_` (e.g. `0x51424e444d41494e` for QBIND MainNet,
//!   `0x51424e4444455600` for DevNet). The literal string `none`
//!   forces `chain_id = null` explicitly. Defaults to whatever
//!   `build_helper_bundle` emits (currently `None`). This is an
//!   evidence-tooling knob used by Run 059 to mint
//!   "signed-mainnet with declared chain_id" (positive) and
//!   "signed-mainnet with wrong chain_id" (negative) fixtures on
//!   the same trust domain shape; it does NOT change signing
//!   semantics (the field is part of the signed preimage and
//!   canonical fingerprint, as
//!   `pqc_trust_bundle::canonical_signing_bytes` /
//!   `canonical_fingerprint` already include it).
//!
//! Optional 7th positional argument: `[revocation_activation_height_for_target]`
//!   Decimal `u64` (or the literal string `none`). If supplied, the
//!   `activation_height` field on the revocation entry emitted by the
//!   selected mode (leaf-revocation OR root-revocation, whichever the
//!   mode emits) is overridden BEFORE signing and BEFORE the canonical
//!   fingerprint is computed. `none` forces `activation_height = null`
//!   explicitly (i.e. legacy Run 050/052 immediate revocation). The
//!   default is the per-mode value from `parse_mode` (`None` for
//!   pre-Run-062 modes, `Some(u64::MAX)` for `*-pending`, `Some(0)`
//!   for `*-active`). This is an evidence-tooling knob used by
//!   Run 062 to mint "future-height pending revocation" and
//!   "currently-active revocation" fixtures on the same trust domain
//!   shape; it does NOT change signing semantics (the field is part
//!   of the signed preimage and canonical fingerprint, as
//!   `pqc_trust_bundle::canonical_signing_bytes` /
//!   `canonical_fingerprint` already include it).
//!
//! Writes to `outdir`:
//!   root.id.hex                — 64 lowercase hex chars (root_key_id)
//!   root.pk.hex                — full ML-DSA-44 root public key
//!   v<N>.cert.bin              — encoded NetworkDelegationCert
//!   v<N>.kem.sk.bin            — KEM secret key bytes (0o600)
//!   trusted-root.spec          — `--p2p-trusted-root` line (DevNet only)
//!   trust-bundle.json          — Run 050/051 PQC trust-anchor bundle
//!   signing-key.id.hex         — (signed modes) bundle-signing key id
//!   signing-key.pk.hex         — (signed modes) bundle-signing public key
//!   signing-key.spec           — (signed modes) `--p2p-trust-bundle-signing-key` line
//!
//! **DevNet only**: the root signing key and the bundle-signing key
//! are generated fresh on every invocation and never written to disk
//! in any form. A fully-production CA / KMS / rotation flow remains
//! out of scope and is tracked under C4 in
//! `docs/whitepaper/contradiction.md`.

use std::fs;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use qbind_crypto::{MlDsa44Backend, MlKem768Backend, KEM_SUITE_ML_KEM_768};
use qbind_node::pqc_devnet_helper::{
    encode_cert, issue_leaf_delegation_cert, mint_devnet_root, LeafCertSpec,
};
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
use qbind_node::pqc_trust_bundle::{
    build_helper_bundle, canonical_fingerprint, cert_leaf_fingerprint, cert_leaf_fingerprint_hex,
    derive_signing_key_id, sign_bundle_devnet_helper, HelperBundleMode, TrustBundle,
    TrustBundleEnvironment, TrustBundleRevocation, TrustBundleSignature,
};

fn vid_bytes(vid: u64) -> [u8; 32] {
    let mut b = [0u8; 32];
    let s = format!("qbind-val-{}", vid);
    let n = s.len().min(32);
    b[..n].copy_from_slice(&s.as_bytes()[..n]);
    b
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Run 051: post-signing tampering knobs for signed-bundle fixtures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignedMode {
    /// Sign as-is.
    Honest,
    /// Sign honestly, then mutate `roots[0].not_after` (so the
    /// signed preimage no longer matches the on-disk bytes).
    TamperRootAfterSigning,
    /// Sign with one keypair, but publish a *different* keypair as
    /// the bundle-signing key spec for the CLI.
    WrongSigningKey,
    /// Sign honestly, then set `signature.suite_id = 99`.
    UnsupportedSuite,
    /// Sign honestly, then truncate `signature.sig_bytes` to 1 byte.
    MalformedSignatureBytes,
    /// Sign honestly, then overwrite `signature.signing_key_id`
    /// with `roots[0].root_id` (collision).
    KeyRootCollision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeafRevocationTarget {
    /// No active leaf revocation in the bundle.
    None,
    /// Revoke the leaf cert of validator `vid` (must be < num_validators).
    Validator(u64),
    /// Revoke a synthetic all-zeros leaf fingerprint that no real
    /// validator leaf cert produces (Run 054 unknown-fp smoke).
    UnknownAllZeros,
}

/// Run 062: extra revocation gate applied to the revocation entry
/// emitted by the selected mode. When `Some(h)`, the helper writes the
/// revocation entry with `activation_height = Some(h)`; the bundle
/// will accept the revocation as **pending** until `current_height >= h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Run062RevocationGate {
    /// Per-entry `activation_height` override applied to the
    /// leaf-revocation OR root-revocation entry emitted by the mode.
    /// `None` ⇒ legacy Run 050/052 (immediate, no height gate).
    revocation_activation_height: Option<u64>,
    /// When true, also emit a root-level revocation entry (in addition
    /// to whatever leaf-revocation the mode already emits) for the
    /// bundle's `roots[0].root_id` so root-revocation pending/active
    /// smokes can be driven from the helper without redesigning the
    /// mode taxonomy.
    emit_root_revocation: bool,
    /// Run 063: when true, mint a second fresh DevNet root and append
    /// it to `roots[]` BEFORE signing. No leaf cert is issued from the
    /// second root; it exists solely so that an active root-scope
    /// revocation of `roots[0]` (the leaf-issuing root) does not
    /// empty the bundle's active-roots set. This is the smallest
    /// helper extension that lets a release-binary smoke exercise
    /// the Run 063 local revoked-issuer-root self-check on its
    /// negative path (where `roots[0]` is revoked but `roots[1]`
    /// remains active so the Run 050 `trusted_roots.is_empty()` FATAL
    /// does NOT fire before Run 063).
    emit_second_unrelated_root: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Unsigned(HelperBundleMode, Option<TrustBundleEnvironment>),
    Signed(
        TrustBundleEnvironment,
        SignedMode,
        LeafRevocationTarget,
        Run062RevocationGate,
    ),
}

fn parse_mode(s: &str) -> Mode {
    match s {
        // Run 050 unsigned fixtures.
        "valid" => Mode::Unsigned(HelperBundleMode::Valid, None),
        "wrong-environment" => Mode::Unsigned(HelperBundleMode::WrongEnvironment, None),
        "expired-bundle" => Mode::Unsigned(HelperBundleMode::ExpiredBundle, None),
        "expired-root" => Mode::Unsigned(HelperBundleMode::ExpiredRoot, None),
        "root-revocation-listed" => {
            Mode::Unsigned(HelperBundleMode::RootRevocationListed, None)
        }
        "root-status-revoked" => Mode::Unsigned(HelperBundleMode::RootStatusRevoked, None),
        "duplicate-root" => Mode::Unsigned(HelperBundleMode::DuplicateRoot, None),
        "unsupported-suite" => Mode::Unsigned(HelperBundleMode::UnsupportedSuite, None),
        // Run 050 unsigned-on-non-devnet fixtures.
        "unsigned-testnet" => Mode::Unsigned(
            HelperBundleMode::Valid,
            Some(TrustBundleEnvironment::Testnet),
        ),
        "unsigned-mainnet" => Mode::Unsigned(
            HelperBundleMode::Valid,
            Some(TrustBundleEnvironment::Mainnet),
        ),
        // Run 051 signed fixtures.
        "signed-devnet" => Mode::Signed(TrustBundleEnvironment::Devnet, SignedMode::Honest, LeafRevocationTarget::None, Run062RevocationGate { revocation_activation_height: None, emit_root_revocation: false, emit_second_unrelated_root: false }),
        "signed-testnet" => Mode::Signed(TrustBundleEnvironment::Testnet, SignedMode::Honest, LeafRevocationTarget::None, Run062RevocationGate { revocation_activation_height: None, emit_root_revocation: false, emit_second_unrelated_root: false }),
        "signed-mainnet" => Mode::Signed(TrustBundleEnvironment::Mainnet, SignedMode::Honest, LeafRevocationTarget::None, Run062RevocationGate { revocation_activation_height: None, emit_root_revocation: false, emit_second_unrelated_root: false }),
        "signed-tampered" => Mode::Signed(TrustBundleEnvironment::Devnet, SignedMode::TamperRootAfterSigning, LeafRevocationTarget::None, Run062RevocationGate { revocation_activation_height: None, emit_root_revocation: false, emit_second_unrelated_root: false }),
        "signed-wrong-key" => Mode::Signed(TrustBundleEnvironment::Devnet, SignedMode::WrongSigningKey, LeafRevocationTarget::None, Run062RevocationGate { revocation_activation_height: None, emit_root_revocation: false, emit_second_unrelated_root: false }),
        // Run 059 MainNet evidence fixtures: same tamper / wrong-key
        // semantics as the existing DevNet-env signed-tampered /
        // signed-wrong-key modes, but emitted with
        // `environment=mainnet` so the release binary exercises the
        // MainNet bundle path. The env is the only difference from
        // the existing DevNet-env modes; the per-mode signing /
        // tampering logic below is unchanged.
        "signed-mainnet-tampered" => Mode::Signed(TrustBundleEnvironment::Mainnet, SignedMode::TamperRootAfterSigning, LeafRevocationTarget::None, Run062RevocationGate { revocation_activation_height: None, emit_root_revocation: false, emit_second_unrelated_root: false }),
        "signed-mainnet-wrong-key" => Mode::Signed(TrustBundleEnvironment::Mainnet, SignedMode::WrongSigningKey, LeafRevocationTarget::None, Run062RevocationGate { revocation_activation_height: None, emit_root_revocation: false, emit_second_unrelated_root: false }),
        "signed-unsupported-suite" => Mode::Signed(TrustBundleEnvironment::Devnet, SignedMode::UnsupportedSuite, LeafRevocationTarget::None, Run062RevocationGate { revocation_activation_height: None, emit_root_revocation: false, emit_second_unrelated_root: false }),
        "signed-malformed" => Mode::Signed(TrustBundleEnvironment::Devnet, SignedMode::MalformedSignatureBytes, LeafRevocationTarget::None, Run062RevocationGate { revocation_activation_height: None, emit_root_revocation: false, emit_second_unrelated_root: false }),
        "signed-key-root-collision" => Mode::Signed(TrustBundleEnvironment::Devnet, SignedMode::KeyRootCollision, LeafRevocationTarget::None, Run062RevocationGate { revocation_activation_height: None, emit_root_revocation: false, emit_second_unrelated_root: false }),
        // Run 054 signed-bundle leaf-revocation fixtures.
        "signed-devnet-revoked-v0" => Mode::Signed(TrustBundleEnvironment::Devnet, SignedMode::Honest, LeafRevocationTarget::Validator(0), Run062RevocationGate { revocation_activation_height: None, emit_root_revocation: false, emit_second_unrelated_root: false }),
        "signed-devnet-revoked-v1" => Mode::Signed(TrustBundleEnvironment::Devnet, SignedMode::Honest, LeafRevocationTarget::Validator(1), Run062RevocationGate { revocation_activation_height: None, emit_root_revocation: false, emit_second_unrelated_root: false }),
        "signed-devnet-revoked-unknown" => Mode::Signed(TrustBundleEnvironment::Devnet, SignedMode::Honest, LeafRevocationTarget::UnknownAllZeros, Run062RevocationGate { revocation_activation_height: None, emit_root_revocation: false, emit_second_unrelated_root: false }),
        // Run 062 leaf-revocation activation gates. The
        // `[revocation_activation_height_for_target]` positional arg
        // (see `main` below) sets the `activation_height` field on
        // the emitted leaf-revocation entry. With no arg the entry is
        // immediate (legacy Run 052). A `*-pending` mode is intended
        // to be paired with a large value (e.g. u64::MAX) to keep the
        // revocation in the PENDING set at startup. A `*-active`
        // mode is intended to be paired with a value <= current
        // height (e.g. 0) to keep it ACTIVE at startup.
        "signed-devnet-leaf-revocation-pending-v0" => Mode::Signed(
            TrustBundleEnvironment::Devnet,
            SignedMode::Honest,
            LeafRevocationTarget::Validator(0),
            Run062RevocationGate {
                revocation_activation_height: Some(u64::MAX),
                emit_root_revocation: false,
                emit_second_unrelated_root: false,
            },
        ),
        "signed-devnet-leaf-revocation-active-v0" => Mode::Signed(
            TrustBundleEnvironment::Devnet,
            SignedMode::Honest,
            LeafRevocationTarget::Validator(0),
            Run062RevocationGate {
                revocation_activation_height: Some(0),
                emit_root_revocation: false,
                emit_second_unrelated_root: false,
            },
        ),
        // Run 062 root-revocation activation gates. These emit a
        // root-level (no leaf_cert_fingerprint) revocation pointing at
        // the bundle's roots[0]. `*-pending` keeps the root in the
        // active set at startup (revocation deferred); `*-active`
        // excludes it immediately (legacy Run 050 behaviour).
        "signed-devnet-root-revocation-pending" => Mode::Signed(
            TrustBundleEnvironment::Devnet,
            SignedMode::Honest,
            LeafRevocationTarget::None,
            Run062RevocationGate {
                revocation_activation_height: Some(u64::MAX),
                emit_root_revocation: true,
                emit_second_unrelated_root: false,
            },
        ),
        "signed-devnet-root-revocation-active" => Mode::Signed(
            TrustBundleEnvironment::Devnet,
            SignedMode::Honest,
            LeafRevocationTarget::None,
            Run062RevocationGate {
                revocation_activation_height: Some(0),
                emit_root_revocation: true,
                emit_second_unrelated_root: false,
            },
        ),
        // Run 063 issuer-root local revocation startup self-check
        // fixtures. Both modes mint a SECOND fresh DevNet root and
        // append it to `roots[]` BEFORE signing, then root-revoke
        // `roots[0]` (the root from which all v0..vN leaf certs are
        // issued). With a second still-active root in place, the
        // bundle's `active_roots` set is non-empty even after
        // `roots[0]` is revoked, so the Run 050
        // `trusted_roots.is_empty()` FATAL does NOT fire — giving
        // the Run 063 startup self-check a chance to evaluate the
        // local leaf's issuing root against the active
        // `revoked_root_ids` set.
        //
        //   - `*-active-v0` uses `activation_height = None` so the
        //     revocation is immediately active under the binary's
        //     `validate_at_with_signing_keys_chain_id_and_revocation_
        //     activation` loader (Run 062). The expected outcome is
        //     that the Run 063 FATAL fires when the operator points
        //     `--p2p-leaf-cert` at `v0.cert.bin` (whose issuer is the
        //     revoked `roots[0]`).
        //   - `*-pending-v0` uses `activation_height = u64::MAX` so
        //     the revocation stays PENDING under the binary's
        //     loader. The expected outcome is that the Run 063
        //     self-check does NOT fire (pending entries do not
        //     appear in `revoked_root_ids`), so the node starts
        //     cleanly even though the bundle DECLARES the v0
        //     issuer's root revoked.
        "signed-devnet-issuer-root-revocation-active-v0" => Mode::Signed(
            TrustBundleEnvironment::Devnet,
            SignedMode::Honest,
            LeafRevocationTarget::None,
            Run062RevocationGate {
                revocation_activation_height: None,
                emit_root_revocation: true,
                emit_second_unrelated_root: true,
            },
        ),
        "signed-devnet-issuer-root-revocation-pending-v0" => Mode::Signed(
            TrustBundleEnvironment::Devnet,
            SignedMode::Honest,
            LeafRevocationTarget::None,
            Run062RevocationGate {
                revocation_activation_height: Some(u64::MAX),
                emit_root_revocation: true,
                emit_second_unrelated_root: true,
            },
        ),
        other => panic!(
            "unknown bundle_mode `{}` (expected one of: \
             valid / wrong-environment / expired-bundle / expired-root / \
             root-revocation-listed / root-status-revoked / duplicate-root / \
             unsupported-suite / unsigned-testnet / unsigned-mainnet / \
             signed-devnet / signed-testnet / signed-mainnet / signed-tampered / \
             signed-wrong-key / signed-mainnet-tampered / signed-mainnet-wrong-key / \
             signed-unsupported-suite / signed-malformed / \
             signed-key-root-collision / signed-devnet-revoked-v0 / \
             signed-devnet-revoked-v1 / signed-devnet-revoked-unknown / \
             signed-devnet-leaf-revocation-pending-v0 / \
             signed-devnet-leaf-revocation-active-v0 / \
             signed-devnet-root-revocation-pending / \
             signed-devnet-root-revocation-active / \
             signed-devnet-issuer-root-revocation-active-v0 / \
             signed-devnet-issuer-root-revocation-pending-v0)",
            other
        ),
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let outdir = args
        .next()
        .expect("usage: devnet_pqc_trust_bundle_helper <outdir> <num_validators> [bundle_mode]");
    let num_validators: u64 = args
        .next()
        .expect("usage: devnet_pqc_trust_bundle_helper <outdir> <num_validators> [bundle_mode]")
        .parse()
        .expect("num_validators must be a u64");
    let bundle_mode_arg = args.next().unwrap_or_else(|| "valid".to_string());
    let mode = parse_mode(&bundle_mode_arg);
    let sequence_override: Option<u64> = args.next().map(|s| {
        s.parse::<u64>()
            .expect("optional [sequence_override] must be a u64 decimal")
    });
    // Run 067: accept either `none` (forces `activation_height = null`
    // explicitly, equivalent to omitting this positional when no later
    // positional is needed) or a decimal `u64`. The outer `Option<...>`
    // wraps whether the positional was supplied; the inner
    // `Option<u64>` is the value to write into
    // `bundle.activation_height`.
    let activation_height_override: Option<Option<u64>> = args.next().map(|s| {
        if s.eq_ignore_ascii_case("none") {
            None
        } else {
            Some(
                s.parse::<u64>()
                    .expect("optional [activation_height_override] must be a u64 decimal or 'none'"),
            )
        }
    });
    // Run 059: optional bundle `chain_id` override. The string `none`
    // forces `chain_id = null` explicitly; any other value is written
    // verbatim into the bundle (the loader parses it the same way it
    // parses operator-supplied chain ids).
    let chain_id_override: Option<Option<String>> = args.next().map(|s| {
        if s.eq_ignore_ascii_case("none") {
            None
        } else {
            Some(s)
        }
    });
    // Run 062: optional per-entry `activation_height` override applied
    // to the revocation entry emitted by the selected mode (leaf-
    // revocation or root-revocation). Overrides any default value the
    // mode set in `parse_mode`. `none` forces `activation_height =
    // null` explicitly (legacy Run 050/052 immediate revocation).
    let revocation_activation_height_for_target_override: Option<Option<u64>> =
        args.next().map(|s| {
            if s.eq_ignore_ascii_case("none") {
                None
            } else {
                Some(
                    s.parse::<u64>()
                        .expect("optional [revocation_activation_height_for_target] must be a u64 decimal or 'none'"),
                )
            }
        });

    fs::create_dir_all(&outdir).expect("mkdir outdir");

    let root = mint_devnet_root().expect("root keygen");
    let root_id_hex = hex_lower(&root.root_key_id);
    let root_pk_hex = hex_lower(&root.root_pk);

    fs::write(format!("{}/root.id.hex", outdir), &root_id_hex).expect("write root.id.hex");
    fs::write(format!("{}/root.pk.hex", outdir), &root_pk_hex).expect("write root.pk.hex");

    let trusted_spec = format!(
        "{}:{}:{}",
        root_id_hex, PQC_TRANSPORT_SUITE_ML_DSA_44, root_pk_hex
    );
    fs::write(format!("{}/trusted-root.spec", outdir), &trusted_spec)
        .expect("write trusted-root.spec");

    let mut issued_leaf_fps: Vec<(u64, String)> = Vec::new();
    for vid in 0..num_validators {
        let (kem_pk, kem_sk) = MlKem768Backend::generate_keypair().expect("ML-KEM-768 keygen");
        let spec = LeafCertSpec::currently_valid(vid_bytes(vid), root.root_key_id, kem_pk);
        let cert = issue_leaf_delegation_cert(&spec, &root.root_sk).expect("issue leaf cert");

        let leaf_fp = cert_leaf_fingerprint(&cert);
        let leaf_fp_hex = cert_leaf_fingerprint_hex(&leaf_fp);
        issued_leaf_fps.push((vid, leaf_fp_hex.clone()));
        fs::write(format!("{}/v{}.leaf-fp.hex", outdir, vid), &leaf_fp_hex)
            .expect("write v{vid}.leaf-fp.hex");

        fs::write(format!("{}/v{}.cert.bin", outdir, vid), encode_cert(&cert))
            .expect("write cert");

        let sk_path = format!("{}/v{}.kem.sk.bin", outdir, vid);
        fs::write(&sk_path, &kem_sk).expect("write kem sk");
        #[cfg(unix)]
        fs::set_permissions(&sk_path, fs::Permissions::from_mode(0o600))
            .expect("chmod kem sk 0600");
    }

    let generated_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let bundle: TrustBundle = match mode {
        Mode::Unsigned(helper_mode, env_override) => {
            let mut b = build_helper_bundle(helper_mode, &root_id_hex, &root_pk_hex, generated_at);
            if let Some(env) = env_override {
                b.environment = env;
            }
            if let Some(seq) = sequence_override {
                b.sequence = seq;
            }
            if let Some(maybe_h) = activation_height_override {
                // Run 057/067: bundle-level activation_height set before
                // fingerprint computation; unsigned paths still cover
                // the field via the canonical fingerprint. `None`
                // explicitly clears the field.
                b.activation_height = maybe_h;
            }
            // Run 059: bundle.chain_id override before fingerprint
            // computation.
            if let Some(maybe_cid) = chain_id_override.clone() {
                b.chain_id = maybe_cid;
            }
            b
        }
        Mode::Signed(env, signed_mode, leaf_revocation_target, run062_gate) => {
            let mut b = build_helper_bundle(
                HelperBundleMode::Valid,
                &root_id_hex,
                &root_pk_hex,
                generated_at,
            );
            b.environment = env;
            if let Some(seq) = sequence_override {
                // Run 056: override sequence BEFORE signing so the
                // signed preimage covers the requested sequence.
                b.sequence = seq;
            }
            if let Some(maybe_h) = activation_height_override {
                // Run 057/067: override bundle-level activation_height
                // BEFORE signing so the signed preimage covers it.
                // `None` explicitly clears the field (Run 067 positive
                // MainNet smoke needs this combined with
                // `chain_id_override` on a fresh data dir).
                b.activation_height = maybe_h;
            }
            // Run 059: override bundle.chain_id BEFORE signing so
            // the signed preimage covers the declared chain_id.
            if let Some(maybe_cid) = chain_id_override.clone() {
                b.chain_id = maybe_cid;
            }

            // Run 054: inject an active leaf-cert revocation for the
            // requested target before signing, so the signed preimage
            // covers the revocation entry.
            //
            // Run 062: the per-entry `activation_height` field is
            // resolved as follows:
            //   1. If the operator supplied
            //      `[revocation_activation_height_for_target]` on the
            //      command line, that value (or `None` when `none` was
            //      passed) wins, regardless of mode default.
            //   2. Else, the mode default from `parse_mode` wins
            //      (`Run062RevocationGate.revocation_activation_height`).
            let revocation_activation_height_for_target: Option<u64> =
                match revocation_activation_height_for_target_override {
                    Some(maybe) => maybe,
                    None => run062_gate.revocation_activation_height,
                };
            match leaf_revocation_target {
                LeafRevocationTarget::None => {}
                LeafRevocationTarget::Validator(target_vid) => {
                    let (_, fp_hex) = issued_leaf_fps
                        .iter()
                        .find(|(vid, _)| *vid == target_vid)
                        .unwrap_or_else(|| {
                            panic!(
                                "signed-devnet-revoked-v{} requires num_validators > {}",
                                target_vid, target_vid
                            )
                        });
                    b.revocations.push(TrustBundleRevocation {
                        root_id: root_id_hex.clone(),
                        leaf_cert_fingerprint: Some(fp_hex.clone()),
                        reason: "test-leaf-revocation-run054".to_string(),
                        effective_from: 0,
                        activation_height: revocation_activation_height_for_target,
                    });
                }
                LeafRevocationTarget::UnknownAllZeros => {
                    // Run 054: revoke an all-zeros leaf fingerprint
                    // that no real validator leaf cert can produce
                    // (cert_leaf_fingerprint is a SHA3-256 with a
                    // domain separator and never emits all-zeros for
                    // a real cert in practice).
                    b.revocations.push(TrustBundleRevocation {
                        root_id: root_id_hex.clone(),
                        leaf_cert_fingerprint: Some(
                            "0000000000000000000000000000000000000000000000000000000000000000"
                                .to_string(),
                        ),
                        reason: "test-leaf-revocation-run054-unknown-fp".to_string(),
                        effective_from: 0,
                        activation_height: revocation_activation_height_for_target,
                    });
                }
            }

            // Run 062: emit a root-level revocation entry when the
            // mode requests it. The entry's `activation_height`
            // follows the same resolution rule as the leaf-revocation
            // path above (CLI override > mode default).
            if run062_gate.emit_root_revocation {
                b.revocations.push(TrustBundleRevocation {
                    root_id: root_id_hex.clone(),
                    leaf_cert_fingerprint: None,
                    reason: "test-root-revocation-run062".to_string(),
                    effective_from: 0,
                    activation_height: revocation_activation_height_for_target,
                });
            }

            // Run 063: append a SECOND fresh DevNet root to `roots[]`
            // BEFORE signing when the mode requests it. No leaf cert
            // is issued from this root — its sole purpose is to keep
            // the bundle's `active_roots` set non-empty after an
            // active root-scope revocation of `roots[0]` (the leaf-
            // issuing root). This lets the Run 063 startup self-check
            // be exercised on the live release binary without the
            // Run 050 `trusted_roots.is_empty()` FATAL firing first.
            // The second root's `root_pk` is a fresh ephemeral
            // ML-DSA-44 public key; the corresponding secret key is
            // discarded (never written to disk and never used).
            if run062_gate.emit_second_unrelated_root {
                let second_root = mint_devnet_root().expect("second root keygen");
                let second_root_id_hex = hex_lower(&second_root.root_key_id);
                let second_root_pk_hex = hex_lower(&second_root.root_pk);
                b.roots.push(qbind_node::pqc_trust_bundle::TrustBundleRoot {
                    root_id: second_root_id_hex.clone(),
                    suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
                    root_pk: second_root_pk_hex.clone(),
                    not_before: 0,
                    not_after: u64::MAX,
                    status: qbind_node::pqc_trust_bundle::RootStatus::Active,
                    activation_epoch: None,
                    activation_height: None,
                });
                // Emit a side-channel file so a smoke can record the
                // identity of the second still-active root for the
                // evidence doc.
                fs::write(
                    format!("{}/second-root.id.hex", outdir),
                    &second_root_id_hex,
                )
                .expect("write second-root.id.hex");
            }

            // Mint a fresh bundle-signing keypair. NEVER written to disk.
            let (signing_pk, signing_sk) =
                MlDsa44Backend::generate_keypair().expect("ML-DSA-44 signing keygen");
            let signing_id = derive_signing_key_id(&signing_pk);
            let signing_id_hex = hex_lower(&signing_id);
            let signing_pk_hex = hex_lower(&signing_pk);

            // Decide what (pk, sk) to *publish* to the operator as
            // the verification key spec — for `WrongSigningKey` we
            // publish an unrelated keypair so verification fails.
            let (pub_id_hex, pub_pk_hex) = if signed_mode == SignedMode::WrongSigningKey {
                let (other_pk, _other_sk) =
                    MlDsa44Backend::generate_keypair().expect("ML-DSA-44 other keygen");
                let other_id = derive_signing_key_id(&other_pk);
                (hex_lower(&other_id), hex_lower(&other_pk))
            } else {
                (signing_id_hex.clone(), signing_pk_hex.clone())
            };

            // For KeyRootCollision: publish a signing-key spec that
            // happens to use the root id as its KEYID (operator typo).
            let (pub_id_hex, pub_pk_hex) = if signed_mode == SignedMode::KeyRootCollision {
                (root_id_hex.clone(), pub_pk_hex)
            } else {
                (pub_id_hex, pub_pk_hex)
            };

            // Sign the bundle.
            let mut sig = sign_bundle_devnet_helper(&b, signing_id, &signing_sk)
                .expect("sign trust bundle");

            // Apply post-signing tampering as requested.
            match signed_mode {
                SignedMode::Honest | SignedMode::WrongSigningKey => {}
                SignedMode::TamperRootAfterSigning => {
                    // Mutate not_after — fingerprint changes;
                    // signature still references the original.
                    b.roots[0].not_after = b.roots[0].not_after.wrapping_sub(1);
                }
                SignedMode::UnsupportedSuite => {
                    sig.suite_id = 99;
                }
                SignedMode::MalformedSignatureBytes => {
                    sig.sig_bytes = "ab".to_string();
                }
                SignedMode::KeyRootCollision => {
                    sig.signing_key_id = root_id_hex.clone();
                }
            }
            b.signature = Some(sig);

            // Write signing-key fixtures.
            fs::write(
                format!("{}/signing-key.id.hex", outdir),
                &pub_id_hex,
            )
            .expect("write signing-key.id.hex");
            fs::write(
                format!("{}/signing-key.pk.hex", outdir),
                &pub_pk_hex,
            )
            .expect("write signing-key.pk.hex");
            let signing_spec = format!(
                "{}:{}:{}",
                pub_id_hex, PQC_TRANSPORT_SUITE_ML_DSA_44, pub_pk_hex
            );
            fs::write(format!("{}/signing-key.spec", outdir), &signing_spec)
                .expect("write signing-key.spec");

            b
        }
    };

    let bundle_json = serde_json::to_vec_pretty(&bundle).expect("serialize trust bundle");
    let bundle_path = format!("{}/trust-bundle.json", outdir);
    fs::write(&bundle_path, &bundle_json).expect("write trust-bundle.json");

    let fp = canonical_fingerprint(&bundle);
    let fp_hex = hex_lower(&fp);

    let signed_summary = match bundle.signature.as_ref() {
        None => "unsigned".to_string(),
        Some(TrustBundleSignature {
            signing_key_id,
            suite_id,
            sig_bytes,
        }) => format!(
            "signed(signing_key_id={}.. suite={} sig_len_hex={})",
            &signing_key_id.chars().take(8).collect::<String>(),
            suite_id,
            sig_bytes.len(),
        ),
    };

    eprintln!(
        "[devnet_pqc_trust_bundle_helper] DEVNET-EPHEMERAL: root_id={} sig_suite={} kem_suite={} \
         validators={} bundle_mode={} bundle_env={} bundle_sequence={} \
         bundle_activation_height={:?} bundle_chain_id={:?} bundle_fingerprint={} \
         signature={} bundle_path={} outdir={}",
        root_id_hex,
        PQC_TRANSPORT_SUITE_ML_DSA_44,
        KEM_SUITE_ML_KEM_768,
        num_validators,
        bundle_mode_arg,
        bundle.environment,
        bundle.sequence,
        bundle.activation_height,
        bundle.chain_id,
        fp_hex,
        signed_summary,
        bundle_path,
        outdir,
    );
    eprintln!(
        "[devnet_pqc_trust_bundle_helper] root_sk and bundle signing_sk were held in memory \
         only; never written to disk."
    );

    // Print the trusted-root spec on stdout for shell capture (matches
    // the Run 037 helper's contract); the bundle path is on stderr.
    println!("{}", trusted_spec);
}