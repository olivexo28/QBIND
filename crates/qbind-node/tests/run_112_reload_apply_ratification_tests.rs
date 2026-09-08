//! Run 112 — integration tests for the **process-start reload-apply
//! bundle-signing-key ratification enforcement** layer wired into
//! `qbind_node::pqc_trust_reload::apply_validated_candidate_with_previous_and_ratification`.
//!
//! These tests prove three invariants:
//!
//!   * A valid ratification + matching bundle-signing key under
//!     Strict policy passes the preflight and falls through to the
//!     existing Run 070 `validate → snapshot → swap → evict → commit`
//!     ordering bit-for-bit.
//!   * Missing / bad / wrong-chain / wrong-environment / unknown-root
//!     ratification under Strict policy refuses the apply BEFORE any
//!     snapshot, swap, eviction, or sequence commit; the
//!     `FakeLiveTrustApplyContext` records ZERO callback events on
//!     every rejection path.
//!   * The persistence file is never created or rewritten by a
//!     rejected apply, and the in-memory live fingerprint stays at
//!     its pre-apply value.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_112.md`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use qbind_crypto::MlDsa44Backend;
use qbind_ledger::{
    bundle_signing_ratification::test_helpers as ratification_helpers,
    compute_canonical_genesis_hash, BundleSigningRatification, GenesisAllocation,
    GenesisAuthorityConfig, GenesisAuthorityRoot, GenesisConfig, GenesisCouncilConfig,
    GenesisHash, GenesisMonetaryConfig, GenesisValidator, NetworkEnvironmentPolicy,
    RatificationEnforcementFailure, RatificationEnforcementPolicy, RatificationEnvironment,
    RatificationFailure, GENESIS_AUTHORITY_SUITE_ML_DSA_44,
};
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
use qbind_node::pqc_trust_activation::ActivationContext;
use qbind_node::pqc_trust_bundle::{
    derive_signing_key_id, sign_bundle_devnet_helper, BundleSigningKey, BundleSigningKeySet,
    LoadedTrustBundle, RootStatus, TrustBundle, TrustBundleEnvironment, TrustBundleRevocation,
    TrustBundleRoot,
};
use qbind_node::pqc_trust_reload::{
    apply_validated_candidate_with_previous_and_ratification, ApplyMode, LiveTrustApplyContext,
    RatificationEnforcementContext, ReloadApplyError, ReloadCheckError, ReloadCheckInputs,
};
use qbind_node::pqc_trust_sequence::{chain_id_hex, sequence_file_path};
use qbind_types::NetworkEnvironment;

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

fn hex_lower(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", x);
    }
    s
}

fn tmpdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "qbind-run112-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    std::fs::create_dir_all(&p).expect("create_dir_all");
    p
}

struct Harness {
    signing_keys: BundleSigningKeySet,
    signing_pk: Vec<u8>,
    signing_key_id: [u8; 32],
    signing_sk: Vec<u8>,
    root_id_hex: String,
    root_pk_hex: String,
    authority_pk: Vec<u8>,
    authority_sk: Vec<u8>,
    genesis_cfg: GenesisConfig,
    canonical_hash: GenesisHash,
    chain_id_str: String,
    env_policy: NetworkEnvironmentPolicy,
}

fn devnet_harness() -> Harness {
    let (signing_pk, signing_sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen signing key");
    let signing_key_id = derive_signing_key_id(&signing_pk);
    let signing_keys = BundleSigningKeySet::from_keys_unchecked(vec![BundleSigningKey {
        key_id_bytes: signing_key_id,
        suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
        pk_bytes: signing_pk.clone(),
    }]);
    let root = mint_devnet_root().expect("mint devnet root");
    let (authority_pk, authority_sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen authority key");
    let chain_id = NetworkEnvironment::Devnet.chain_id();
    let chain_id_str = chain_id_hex(chain_id);
    let mut genesis_cfg = GenesisConfig::new(
        &chain_id_str,
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
    let auth_root = GenesisAuthorityRoot::new(
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        &hex_lower(&authority_pk),
        "test-bundle-signing-1",
    );
    genesis_cfg.authority = Some(GenesisAuthorityConfig::new(vec![auth_root]));
    let env_policy = NetworkEnvironmentPolicy::Devnet;
    let canonical_hash = compute_canonical_genesis_hash(&genesis_cfg, env_policy);

    Harness {
        signing_keys,
        signing_pk,
        signing_key_id,
        signing_sk,
        root_id_hex: hex_lower(&root.root_key_id),
        root_pk_hex: hex_lower(&root.root_pk),
        authority_pk,
        authority_sk,
        genesis_cfg,
        canonical_hash,
        chain_id_str,
        env_policy,
    }
}

fn build_signed_bundle(h: &Harness, sequence: u64, generated_at: u64) -> TrustBundle {
    let mut bundle = TrustBundle {
        bundle_version: TrustBundle::SUPPORTED_SCHEMA_VERSION,
        environment: TrustBundleEnvironment::Devnet,
        chain_id: Some(h.chain_id_str.clone()),
        generated_at,
        valid_from: 0,
        valid_until: u64::MAX,
        sequence,
        roots: vec![TrustBundleRoot {
            root_id: h.root_id_hex.clone(),
            suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
            root_pk: h.root_pk_hex.clone(),
            status: RootStatus::Active,
            not_before: 0,
            not_after: u64::MAX,
            activation_epoch: None,
            activation_height: None,
        }],
        revocations: Vec::<TrustBundleRevocation>::new(),
        signature: None,
        activation_epoch: None,
        activation_height: None,
    };
    let sig = sign_bundle_devnet_helper(&bundle, h.signing_key_id, &h.signing_sk).expect("sign");
    bundle.signature = Some(sig);
    bundle
}

fn write_bundle(dir: &Path, name: &str, bundle: &TrustBundle) -> PathBuf {
    let path = dir.join(name);
    let bytes = serde_json::to_vec(bundle).expect("serialise");
    std::fs::write(&path, &bytes).expect("write");
    path
}

fn build_valid_ratification(h: &Harness) -> BundleSigningRatification {
    ratification_helpers::build_signed_ratification(
        &h.chain_id_str,
        RatificationEnvironment::Devnet,
        h.canonical_hash,
        &hex_lower(&h.authority_pk),
        &h.authority_sk,
        &h.signing_pk,
    )
}

fn devnet_inputs<'a>(
    candidate_path: &'a Path,
    signing_keys: &'a BundleSigningKeySet,
    seq_path: Option<&'a Path>,
) -> ReloadCheckInputs<'a> {
    ReloadCheckInputs {
        candidate_path,
        environment: NetworkEnvironment::Devnet,
        chain_id: NetworkEnvironment::Devnet.chain_id(),
        validation_time_secs: 100,
        signing_keys,
        activation_ctx: ActivationContext::height_only(0),
        sequence_persistence_path: seq_path,
        local_leaf_cert_bytes: None,
    }
}

// ---------------------------------------------------------------------
// FakeLiveTrustApplyContext (deterministic; records every callback).
// ---------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
struct CallLog {
    events: Vec<String>,
}

impl CallLog {
    fn push(&mut self, ev: &str) {
        self.events.push(ev.to_string());
    }
}

struct FakeLiveTrustApplyContext {
    log: Arc<Mutex<CallLog>>,
    active_fingerprint: Arc<Mutex<String>>,
}

impl FakeLiveTrustApplyContext {
    fn new(initial_fingerprint: &str) -> Self {
        Self {
            log: Arc::new(Mutex::new(CallLog::default())),
            active_fingerprint: Arc::new(Mutex::new(initial_fingerprint.to_string())),
        }
    }
    fn log(&self) -> Arc<Mutex<CallLog>> {
        self.log.clone()
    }
    fn active(&self) -> Arc<Mutex<String>> {
        self.active_fingerprint.clone()
    }
}

impl LiveTrustApplyContext for FakeLiveTrustApplyContext {
    fn snapshot_active(&mut self) -> Result<Box<dyn std::any::Any + Send + Sync>, String> {
        self.log.lock().unwrap().push("snapshot_active");
        let prev: String = self.active_fingerprint.lock().unwrap().clone();
        Ok(Box::new(prev))
    }
    fn swap_trust_state(&mut self, candidate: &LoadedTrustBundle) -> Result<(), String> {
        self.log.lock().unwrap().push("swap_trust_state");
        let new_fp_prefix = candidate.fingerprint_hex()[..8].to_string();
        *self.active_fingerprint.lock().unwrap() = new_fp_prefix;
        Ok(())
    }
    fn evict_sessions(&mut self) -> Result<usize, String> {
        self.log.lock().unwrap().push("evict_sessions");
        Ok(0)
    }
    fn commit_sequence(&mut self, _candidate: &LoadedTrustBundle) -> Result<(), String> {
        self.log.lock().unwrap().push("commit_sequence");
        Ok(())
    }
    fn rollback_trust_state(
        &mut self,
        snapshot: Box<dyn std::any::Any + Send + Sync>,
    ) -> Result<(), String> {
        self.log.lock().unwrap().push("rollback_trust_state");
        if let Ok(prev) = snapshot.downcast::<String>() {
            *self.active_fingerprint.lock().unwrap() = *prev;
        }
        Ok(())
    }
}

fn assert_no_apply_callbacks(log: &Arc<Mutex<CallLog>>) {
    let events = log.lock().unwrap().events.clone();
    assert!(
        events.is_empty(),
        "Run 112: ratification refusal must occur BEFORE any apply callback; got {:?}",
        events
    );
}

fn assert_seq_file_absent(path: &Path) {
    assert!(
        !path.exists(),
        "Run 112: refused apply must not create persistence file at {}",
        path.display()
    );
}

// =====================================================================
// Tests
// =====================================================================

/// Scenario 1 (Strict / valid): a valid ratification + matching
/// bundle-signing key under Strict policy passes the preflight and
/// drives the existing Run 070 ordering bit-for-bit.
#[test]
fn run112_valid_ratification_under_strict_completes_apply_with_run070_ordering() {
    let h = devnet_harness();
    let dir = tmpdir("valid");
    let seq_path = sequence_file_path(&dir);
    let bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "cand.json", &bundle);
    let ratification = build_valid_ratification(&h);
    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let log = ctx.log();
    let active = ctx.active();

    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path));
    let ratification_ctx = RatificationEnforcementContext {
        authority: h.genesis_cfg.authority.as_ref().unwrap(),
        expected_genesis_hash: &h.canonical_hash,
        expected_environment_policy: h.env_policy,
        expected_chain_id_str: &h.chain_id_str,
        ratification: Some(&ratification),
        policy: RatificationEnforcementPolicy::Strict,
    };
    let applied = apply_validated_candidate_with_previous_and_ratification(
        inputs,
        &ratification_ctx,
        ApplyMode::ApplyLive,
        Some(&mut ctx),
        "aaaaaaaa".to_string(),
        Some(1),
    )
    .expect("valid ratification + apply must succeed");
    assert_eq!(applied.validated.sequence, 2);
    assert_eq!(applied.previous_fingerprint_prefix, "aaaaaaaa");
    assert_eq!(applied.previous_sequence, Some(1));

    // Run 070 ordering preserved bit-for-bit.
    let events = log.lock().unwrap().events.clone();
    assert_eq!(
        events,
        vec![
            "snapshot_active",
            "swap_trust_state",
            "evict_sessions",
            "commit_sequence",
        ]
    );
    // Live state advanced to the new bundle.
    assert_ne!(active.lock().unwrap().as_str(), "aaaaaaaa");
}

/// Scenario 2 (Strict / missing): Strict policy + `ratification=None`
/// → `Missing` refusal BEFORE snapshot / swap / evict / commit.
#[test]
fn run112_missing_ratification_under_strict_refuses_before_any_mutation() {
    let h = devnet_harness();
    let dir = tmpdir("missing");
    let seq_path = sequence_file_path(&dir);
    let bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "cand.json", &bundle);
    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let log = ctx.log();
    let active = ctx.active();

    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path));
    let ratification_ctx = RatificationEnforcementContext {
        authority: h.genesis_cfg.authority.as_ref().unwrap(),
        expected_genesis_hash: &h.canonical_hash,
        expected_environment_policy: h.env_policy,
        expected_chain_id_str: &h.chain_id_str,
        ratification: None,
        policy: RatificationEnforcementPolicy::Strict,
    };
    let err = apply_validated_candidate_with_previous_and_ratification(
        inputs,
        &ratification_ctx,
        ApplyMode::ApplyLive,
        Some(&mut ctx),
        "aaaaaaaa".to_string(),
        Some(1),
    )
    .expect_err("missing ratification under Strict must refuse the apply");
    match err {
        ReloadApplyError::ValidationFailed(ReloadCheckError::RatificationRefused(
            RatificationEnforcementFailure::Missing { .. },
        )) => {}
        other => panic!("expected ValidationFailed(RatificationRefused(Missing)), got {:?}", other),
    }
    assert_no_apply_callbacks(&log);
    assert_seq_file_absent(&seq_path);
    assert_eq!(active.lock().unwrap().as_str(), "aaaaaaaa");
}

/// Scenario 3 (Strict / bad-signature): a tampered ratification
/// signature is refused; no apply callback runs.
#[test]
fn run112_bad_signature_ratification_under_strict_refuses_before_any_mutation() {
    let h = devnet_harness();
    let dir = tmpdir("bad-sig");
    let seq_path = sequence_file_path(&dir);
    let bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "cand.json", &bundle);

    // Build a valid ratification then flip a signature byte to force a
    // PQC verification failure.
    let mut tampered = build_valid_ratification(&h);
    tampered.signature[0] ^= 0xFF;

    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let log = ctx.log();

    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path));
    let ratification_ctx = RatificationEnforcementContext {
        authority: h.genesis_cfg.authority.as_ref().unwrap(),
        expected_genesis_hash: &h.canonical_hash,
        expected_environment_policy: h.env_policy,
        expected_chain_id_str: &h.chain_id_str,
        ratification: Some(&tampered),
        policy: RatificationEnforcementPolicy::Strict,
    };
    let err = apply_validated_candidate_with_previous_and_ratification(
        inputs,
        &ratification_ctx,
        ApplyMode::ApplyLive,
        Some(&mut ctx),
        "aaaaaaaa".to_string(),
        Some(1),
    )
    .expect_err("bad-signature ratification must refuse");
    assert!(matches!(
        err,
        ReloadApplyError::ValidationFailed(ReloadCheckError::RatificationRefused(
            RatificationEnforcementFailure::Verifier(_)
        ))
    ));
    assert_no_apply_callbacks(&log);
    assert_seq_file_absent(&seq_path);
}

/// Scenario 4 (Strict / wrong-chain): a ratification naming a chain
/// id different from the runtime is refused with
/// `Verifier(ChainMismatch)`.
#[test]
fn run112_wrong_chain_ratification_refuses_before_any_mutation() {
    let h = devnet_harness();
    let dir = tmpdir("wrong-chain");
    let seq_path = sequence_file_path(&dir);
    let bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "cand.json", &bundle);
    let bad = ratification_helpers::build_signed_ratification(
        "not-the-runtime-chain",
        RatificationEnvironment::Devnet,
        h.canonical_hash,
        &hex_lower(&h.authority_pk),
        &h.authority_sk,
        &h.signing_pk,
    );

    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let log = ctx.log();

    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path));
    let ratification_ctx = RatificationEnforcementContext {
        authority: h.genesis_cfg.authority.as_ref().unwrap(),
        expected_genesis_hash: &h.canonical_hash,
        expected_environment_policy: h.env_policy,
        expected_chain_id_str: &h.chain_id_str,
        ratification: Some(&bad),
        policy: RatificationEnforcementPolicy::Strict,
    };
    let err = apply_validated_candidate_with_previous_and_ratification(
        inputs,
        &ratification_ctx,
        ApplyMode::ApplyLive,
        Some(&mut ctx),
        "aaaaaaaa".to_string(),
        Some(1),
    )
    .expect_err("wrong-chain ratification must refuse");
    assert!(matches!(
        err,
        ReloadApplyError::ValidationFailed(ReloadCheckError::RatificationRefused(
            RatificationEnforcementFailure::Verifier(RatificationFailure::ChainMismatch { .. })
        ))
    ));
    assert_no_apply_callbacks(&log);
    assert_seq_file_absent(&seq_path);
}

/// Scenario 5 (Strict / wrong-environment): a ratification naming a
/// different environment is refused.
#[test]
fn run112_wrong_environment_ratification_refuses_before_any_mutation() {
    let h = devnet_harness();
    let dir = tmpdir("wrong-env");
    let seq_path = sequence_file_path(&dir);
    let bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "cand.json", &bundle);
    let bad = ratification_helpers::build_signed_ratification(
        &h.chain_id_str,
        RatificationEnvironment::Mainnet,
        h.canonical_hash,
        &hex_lower(&h.authority_pk),
        &h.authority_sk,
        &h.signing_pk,
    );

    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let log = ctx.log();

    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path));
    let ratification_ctx = RatificationEnforcementContext {
        authority: h.genesis_cfg.authority.as_ref().unwrap(),
        expected_genesis_hash: &h.canonical_hash,
        expected_environment_policy: h.env_policy,
        expected_chain_id_str: &h.chain_id_str,
        ratification: Some(&bad),
        policy: RatificationEnforcementPolicy::Strict,
    };
    let err = apply_validated_candidate_with_previous_and_ratification(
        inputs,
        &ratification_ctx,
        ApplyMode::ApplyLive,
        Some(&mut ctx),
        "aaaaaaaa".to_string(),
        Some(1),
    )
    .expect_err("wrong-environment ratification must refuse");
    assert!(matches!(
        err,
        ReloadApplyError::ValidationFailed(ReloadCheckError::RatificationRefused(_))
    ));
    assert_no_apply_callbacks(&log);
    assert_seq_file_absent(&seq_path);
}

/// Scenario 6 (Strict / unknown authority root): a ratification
/// produced by an unrelated authority key is refused with
/// `UnknownAuthorityRoot` (or the equivalent Verifier variant).
#[test]
fn run112_unknown_authority_root_ratification_refuses_before_any_mutation() {
    let h = devnet_harness();
    let dir = tmpdir("unknown-root");
    let seq_path = sequence_file_path(&dir);
    let bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "cand.json", &bundle);

    // Different authority key pair — not present in the genesis
    // bundle_signing_authority_roots.
    let (other_auth_pk, other_auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
    let bad = ratification_helpers::build_signed_ratification(
        &h.chain_id_str,
        RatificationEnvironment::Devnet,
        h.canonical_hash,
        &hex_lower(&other_auth_pk),
        &other_auth_sk,
        &h.signing_pk,
    );

    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let log = ctx.log();

    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path));
    let ratification_ctx = RatificationEnforcementContext {
        authority: h.genesis_cfg.authority.as_ref().unwrap(),
        expected_genesis_hash: &h.canonical_hash,
        expected_environment_policy: h.env_policy,
        expected_chain_id_str: &h.chain_id_str,
        ratification: Some(&bad),
        policy: RatificationEnforcementPolicy::Strict,
    };
    let err = apply_validated_candidate_with_previous_and_ratification(
        inputs,
        &ratification_ctx,
        ApplyMode::ApplyLive,
        Some(&mut ctx),
        "aaaaaaaa".to_string(),
        Some(1),
    )
    .expect_err("unknown authority root must refuse");
    assert!(matches!(
        err,
        ReloadApplyError::ValidationFailed(ReloadCheckError::RatificationRefused(_))
    ));
    assert_no_apply_callbacks(&log);
    assert_seq_file_absent(&seq_path);
}

/// Scenario 7 (Strict / wrong-key): a ratification authorising a
/// different bundle-signing key than the candidate is signed with is
/// refused with `RatifiesDifferentKey`; no apply callback fires.
#[test]
fn run112_ratification_for_different_key_refuses_before_any_mutation() {
    let h = devnet_harness();
    let dir = tmpdir("wrong-key");
    let seq_path = sequence_file_path(&dir);
    let bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "cand.json", &bundle);

    let (other_pk, _other_sk) = MlDsa44Backend::generate_keypair().unwrap();
    let bad = ratification_helpers::build_signed_ratification(
        &h.chain_id_str,
        RatificationEnvironment::Devnet,
        h.canonical_hash,
        &hex_lower(&h.authority_pk),
        &h.authority_sk,
        &other_pk,
    );

    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let log = ctx.log();

    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path));
    let ratification_ctx = RatificationEnforcementContext {
        authority: h.genesis_cfg.authority.as_ref().unwrap(),
        expected_genesis_hash: &h.canonical_hash,
        expected_environment_policy: h.env_policy,
        expected_chain_id_str: &h.chain_id_str,
        ratification: Some(&bad),
        policy: RatificationEnforcementPolicy::Strict,
    };
    let err = apply_validated_candidate_with_previous_and_ratification(
        inputs,
        &ratification_ctx,
        ApplyMode::ApplyLive,
        Some(&mut ctx),
        "aaaaaaaa".to_string(),
        Some(1),
    )
    .expect_err("ratification for different key must refuse");
    match err {
        ReloadApplyError::ValidationFailed(ReloadCheckError::RatificationRefused(
            RatificationEnforcementFailure::RatifiesDifferentKey { .. },
        )) => {}
        other => panic!("expected RatifiesDifferentKey, got {:?}", other),
    }
    assert_no_apply_callbacks(&log);
    assert_seq_file_absent(&seq_path);
}

/// Scenario 8 (DevNet legacy / AllowLegacyUnratified): a missing
/// ratification under the legacy DevNet allowance still drives the
/// existing Run 070 apply ordering — proves Run 112 preserves DevNet
/// opt-out ergonomics when the binary chooses the legacy policy.
#[test]
fn run112_devnet_legacy_allow_unratified_still_applies_with_run070_ordering() {
    let h = devnet_harness();
    let dir = tmpdir("devnet-legacy");
    let seq_path = sequence_file_path(&dir);
    let bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "cand.json", &bundle);

    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let log = ctx.log();

    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path));
    let ratification_ctx = RatificationEnforcementContext {
        authority: h.genesis_cfg.authority.as_ref().unwrap(),
        expected_genesis_hash: &h.canonical_hash,
        expected_environment_policy: h.env_policy,
        expected_chain_id_str: &h.chain_id_str,
        ratification: None,
        policy: RatificationEnforcementPolicy::AllowLegacyUnratified,
    };
    let applied = apply_validated_candidate_with_previous_and_ratification(
        inputs,
        &ratification_ctx,
        ApplyMode::ApplyLive,
        Some(&mut ctx),
        "aaaaaaaa".to_string(),
        Some(1),
    )
    .expect("DevNet AllowLegacyUnratified must drive apply");
    assert_eq!(applied.validated.sequence, 2);
    let events = log.lock().unwrap().events.clone();
    assert_eq!(
        events,
        vec![
            "snapshot_active",
            "swap_trust_state",
            "evict_sessions",
            "commit_sequence",
        ]
    );
}

/// Scenario 9 (ValidateOnly + missing ratification): even when the
/// caller requests `ApplyMode::ValidateOnly`, a Strict-policy
/// ratification refusal still short-circuits BEFORE the
/// validate-only output is produced — proving the gate is evaluated
/// as part of the validation stage and not deferred to live-apply.
#[test]
fn run112_validate_only_mode_still_runs_ratification_gate() {
    let h = devnet_harness();
    let dir = tmpdir("validate-only");
    let seq_path = sequence_file_path(&dir);
    let bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "cand.json", &bundle);

    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let log = ctx.log();

    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path));
    let ratification_ctx = RatificationEnforcementContext {
        authority: h.genesis_cfg.authority.as_ref().unwrap(),
        expected_genesis_hash: &h.canonical_hash,
        expected_environment_policy: h.env_policy,
        expected_chain_id_str: &h.chain_id_str,
        ratification: None,
        policy: RatificationEnforcementPolicy::Strict,
    };
    let err = apply_validated_candidate_with_previous_and_ratification(
        inputs,
        &ratification_ctx,
        ApplyMode::ValidateOnly,
        Some(&mut ctx),
        "aaaaaaaa".to_string(),
        Some(1),
    )
    .expect_err("Strict + missing ratification must refuse even under ValidateOnly");
    assert!(matches!(
        err,
        ReloadApplyError::ValidationFailed(ReloadCheckError::RatificationRefused(_))
    ));
    assert_no_apply_callbacks(&log);
    assert_seq_file_absent(&seq_path);
}

// =====================================================================
// Run 106 policy regression for the apply path — proves the
// Run 112 wiring uses the same gate-decision function as the
// reload-check / peer-candidate-check binary paths.
// =====================================================================

#[test]
fn run112_run106_policy_drives_apply_gate_consistently() {
    use qbind_node::pqc_ratification_policy::{
        ratification_gate_decision, GateInvokeReason, GateSkipReason, RatificationGateDecision,
    };

    // MainNet/TestNet always invoke regardless of operator opt-in.
    for opt_in in [false, true] {
        let m = ratification_gate_decision(NetworkEnvironment::Mainnet, opt_in);
        assert_eq!(
            m,
            RatificationGateDecision::Invoke(GateInvokeReason::MainnetDefaultStrict)
        );
        let t = ratification_gate_decision(NetworkEnvironment::Testnet, opt_in);
        assert_eq!(
            t,
            RatificationGateDecision::Invoke(GateInvokeReason::TestnetDefaultStrict)
        );
    }
    // DevNet without opt-in skips; with opt-in invokes.
    assert_eq!(
        ratification_gate_decision(NetworkEnvironment::Devnet, false),
        RatificationGateDecision::Skip(GateSkipReason::DevnetNoOperatorOptIn)
    );
    assert_eq!(
        ratification_gate_decision(NetworkEnvironment::Devnet, true),
        RatificationGateDecision::Invoke(GateInvokeReason::DevnetOperatorOptIn)
    );
}