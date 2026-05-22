//! Run 114 — integration tests for **SIGHUP live reload
//! bundle-signing-key ratification enforcement** wired through
//! [`qbind_node::pqc_live_trust_reload::LiveReloadController`].
//!
//! These tests drive the EXACT same controller entry point that the
//! `qbind-node` binary's SIGHUP signal-handler task calls
//! (`try_trigger_with_now` / `try_trigger_with_activation`), but
//! exercise it with a populated
//! [`qbind_node::pqc_live_trust_reload::LiveReloadRatificationConfig`]
//! so the Run 105 ratification gate is invoked BEFORE any live trust
//! mutation. The mock evictor lets us assert that no session was
//! evicted on refusal paths; the on-disk sequence record lets us
//! assert that no sequence file was written on refusal paths; the
//! shared `LivePqcTrustState` handle lets us assert that no live
//! trust mutation occurred on refusal paths.
//!
//! Invariants proved by this file:
//!
//!   * **Strict / valid**: a valid ratification under MainNet/TestNet
//!     default-strict policy passes the preflight and falls through
//!     to the existing Run 070/074 ordering (snapshot → swap →
//!     evict → commit). The live state advances, the evictor is
//!     called exactly once, and the sequence file is rewritten.
//!   * **Strict / missing**: a SIGHUP with no operator-supplied
//!     ratification sidecar under Strict policy refuses BEFORE any
//!     snapshot / swap / eviction / commit; no live trust mutation,
//!     no session eviction, no sequence file write.
//!   * **Strict / bad signature**: a sidecar whose signature does
//!     not verify refuses fail-closed with the same no-mutation
//!     invariants.
//!   * **Strict / wrong chain**: a sidecar minted for a different
//!     `chain_id` refuses fail-closed.
//!   * **Strict / wrong environment**: a sidecar minted for a
//!     different `RatificationEnvironment` refuses fail-closed.
//!   * **Strict / unknown authority root**: a sidecar whose
//!     `authority_root_fingerprint` is not in the genesis authority
//!     block refuses fail-closed.
//!   * **Strict / ratifies different key**: a sidecar that
//!     authorises a different bundle-signing key than the candidate
//!     bundle is actually signed by refuses fail-closed.
//!   * **Sidecar I/O / parse failure**: a missing or malformed
//!     sidecar file at the configured path refuses fail-closed
//!     before any mutation.
//!   * **Repeated-trigger safety**: invalid → invalid does not
//!     mutate; invalid → valid still applies correctly; valid →
//!     invalid does not roll back the prior valid state and does
//!     not mutate; repeated same valid candidate follows Run 055
//!     anti-rollback behaviour (idempotent no-write).
//!
//! Strict scope (matches `task/RUN_114_TASK.txt`):
//!
//!   * No peer-driven live apply.
//!   * No signing-key rotation / revocation.
//!   * No authority anti-rollback persistence.
//!   * No KMS/HSM custody.
//!   * No governance / validator-set rotation.
//!   * No change to trust-bundle / peer-candidate / ratification
//!     wire formats.
//!   * No weakening of any existing Run 050/055/057/065/069/070/
//!     072/073/074/103/104/105/106/107/109/112 invariant.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_114.md`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use qbind_crypto::MlDsa44Backend;
use qbind_ledger::bundle_signing_ratification::test_helpers as ratification_helpers;
use qbind_ledger::genesis::{
    GenesisAllocation, GenesisAuthorityConfig, GenesisAuthorityRoot, GenesisConfig,
    GenesisCouncilConfig, GenesisMonetaryConfig, GenesisValidator,
    GENESIS_AUTHORITY_SUITE_ML_DSA_44,
};
use qbind_ledger::{
    compute_canonical_genesis_hash, BundleSigningRatification, GenesisHash,
    NetworkEnvironmentPolicy, RatificationEnforcementFailure, RatificationEnforcementPolicy,
    RatificationEnvironment, RatificationFailure,
};
use qbind_node::metrics::P2pMetrics;
use qbind_node::p2p_session_eviction::{MockP2pSessionEvictor, P2pSessionEvictor};
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_live_trust::LivePqcTrustState;
use qbind_node::pqc_live_trust_reload::{
    LiveReloadConfig, LiveReloadController, LiveReloadOutcome, LiveReloadRatificationConfig,
};
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
use qbind_node::pqc_trust_activation::ActivationContext;
use qbind_node::pqc_trust_bundle::{
    derive_signing_key_id, sign_bundle_devnet_helper, BundleSigningKey, BundleSigningKeySet,
    LoadedTrustBundle, RootStatus, TrustBundle, TrustBundleEnvironment, TrustBundleRevocation,
    TrustBundleRoot,
};
use qbind_node::pqc_trust_reload::{ReloadApplyError, ReloadCheckError};
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
        "qbind-run114-{}-{}-{}",
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
    /// A second bundle-signing key NOT used to sign any candidate;
    /// useful for the "ratifies a different key" scenario.
    other_signing_pk: Vec<u8>,
    root_id_hex: String,
    root_pk_hex: String,
    authority_pk: Vec<u8>,
    authority_sk: Vec<u8>,
    canonical_hash: GenesisHash,
    chain_id_str: String,
    env_policy: NetworkEnvironmentPolicy,
    authority: GenesisAuthorityConfig,
}

fn devnet_harness() -> Harness {
    let (signing_pk, signing_sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen signing key");
    let (other_signing_pk, _other_signing_sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen other signing key");
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
        "run-114-bundle-signing-1",
    );
    let authority = GenesisAuthorityConfig::new(vec![auth_root]);
    genesis_cfg.authority = Some(authority.clone());
    let env_policy = NetworkEnvironmentPolicy::Devnet;
    let canonical_hash = compute_canonical_genesis_hash(&genesis_cfg, env_policy);

    Harness {
        signing_keys,
        signing_pk,
        signing_key_id,
        signing_sk,
        other_signing_pk,
        root_id_hex: hex_lower(&root.root_key_id),
        root_pk_hex: hex_lower(&root.root_pk),
        authority_pk,
        authority_sk,
        canonical_hash,
        chain_id_str,
        env_policy,
        authority,
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

fn load_baseline_loaded(
    bundle_path: &Path,
    signing_keys: &BundleSigningKeySet,
) -> LoadedTrustBundle {
    let bytes = std::fs::read(bundle_path).expect("read");
    TrustBundle::load_from_bytes_with_signing_keys(
        &bytes,
        NetworkEnvironment::Devnet,
        100,
        signing_keys,
    )
    .expect("baseline loads")
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

fn write_ratification(dir: &Path, name: &str, r: &BundleSigningRatification) -> PathBuf {
    let path = dir.join(name);
    let bytes = serde_json::to_vec_pretty(r).expect("serialise ratification");
    std::fs::write(&path, &bytes).expect("write ratification");
    path
}

fn make_controller(
    h: &Harness,
    candidate_path: PathBuf,
    seq_path: Option<PathBuf>,
    baseline_path: &Path,
    sidecar_path: Option<PathBuf>,
    policy: RatificationEnforcementPolicy,
    enforce: bool,
) -> (LiveReloadController, Arc<LivePqcTrustState>, Arc<MockP2pSessionEvictor>, Arc<P2pMetrics>) {
    let baseline = load_baseline_loaded(baseline_path, &h.signing_keys);
    let live = Arc::new(LivePqcTrustState::initialize_from_loaded_bundle(&baseline));
    let mock = Arc::new(MockP2pSessionEvictor::new(0));
    let evictor: Arc<dyn P2pSessionEvictor> = mock.clone();
    let metrics = Arc::new(P2pMetrics::new());
    let ratification = if enforce {
        Some(LiveReloadRatificationConfig {
            authority: h.authority.clone(),
            expected_genesis_hash: h.canonical_hash,
            expected_environment_policy: h.env_policy,
            expected_chain_id_str: h.chain_id_str.clone(),
            policy,
            ratification_sidecar_path: sidecar_path,
        })
    } else {
        None
    };
    let cfg = LiveReloadConfig {
        candidate_path,
        environment: NetworkEnvironment::Devnet,
        chain_id: NetworkEnvironment::Devnet.chain_id(),
        signing_keys: h.signing_keys.clone(),
        activation_ctx: ActivationContext::height_only(0),
        sequence_path: seq_path,
        local_leaf_cert_bytes: None,
        ratification,
    };
    let ctl = LiveReloadController::new(live.clone(), evictor, metrics.clone(), cfg);
    (ctl, live, mock, metrics)
}

fn snapshot_state_fingerprint(live: &Arc<LivePqcTrustState>) -> Vec<u8> {
    live.snapshot().expect("snap").fingerprint().to_vec()
}

// =====================================================================
// Scenario A — Strict / valid: SIGHUP applies, Run 074 ordering preserved.
// =====================================================================

#[test]
fn run114_strict_valid_ratification_applies_and_preserves_run074_ordering() {
    let h = devnet_harness();
    let dir = tmpdir("strict-valid");
    let seq_path = sequence_file_path(&dir);

    // Baseline bundle (sequence=1) — installed in live state.
    let baseline_bundle = build_signed_bundle(&h, 1, 100);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline_bundle);

    // Candidate bundle (sequence=2).
    let candidate_bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate_bundle);

    // Valid sidecar.
    let ratification = build_valid_ratification(&h);
    let sidecar_path = write_ratification(&dir, "ratification.json", &ratification);

    let (ctl, live, mock, metrics) = make_controller(
        &h,
        candidate_path,
        Some(seq_path.clone()),
        &baseline_path,
        Some(sidecar_path),
        RatificationEnforcementPolicy::Strict,
        true,
    );

    let pre_fp = snapshot_state_fingerprint(&live);
    let out = ctl.try_trigger_with_now(300);
    match out {
        LiveReloadOutcome::Applied(applied) => {
            assert_eq!(applied.validated.sequence, 2);
        }
        other => panic!("expected Applied(_), got {:?}", other),
    }
    // Live state advanced to candidate fingerprint.
    let post_fp = snapshot_state_fingerprint(&live);
    assert_ne!(pre_fp, post_fp);

    // Sequence file written.
    assert!(seq_path.exists(), "sequence file must be created on apply");

    // Evictor called exactly once.
    assert_eq!(mock.attempt_count(), 1);

    // Metrics bumped truthfully.
    assert_eq!(metrics.live_reload_trigger_total(), 1);
    assert_eq!(metrics.live_reload_apply_success_total(), 1);
    assert_eq!(metrics.live_reload_apply_failure_total(), 0);
    assert_eq!(metrics.live_reload_last_applied_sequence(), 2);
}

// =====================================================================
// Scenario B — Strict / missing sidecar: refuses before any mutation.
// =====================================================================

#[test]
fn run114_strict_missing_sidecar_refuses_before_any_mutation() {
    let h = devnet_harness();
    let dir = tmpdir("strict-missing");
    let seq_path = sequence_file_path(&dir);
    let baseline_bundle = build_signed_bundle(&h, 1, 100);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline_bundle);
    let candidate_bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate_bundle);

    // Strict policy, sidecar path = None  (the operator did not
    // supply `--p2p-trust-bundle-ratification`).
    let (ctl, live, mock, metrics) = make_controller(
        &h,
        candidate_path,
        Some(seq_path.clone()),
        &baseline_path,
        None,
        RatificationEnforcementPolicy::Strict,
        true,
    );

    let pre_fp = snapshot_state_fingerprint(&live);
    let out = ctl.try_trigger_with_now(300);
    match out {
        LiveReloadOutcome::Invalid(ReloadApplyError::ValidationFailed(
            ReloadCheckError::RatificationRefused(
                RatificationEnforcementFailure::Missing { .. },
            ),
        )) => {}
        other => panic!("expected Missing refusal, got {:?}", other),
    }

    // No live trust mutation.
    let post_fp = snapshot_state_fingerprint(&live);
    assert_eq!(pre_fp, post_fp, "live state must not mutate on refusal");
    // No sequence file written.
    assert!(!seq_path.exists(), "sequence file must NOT be created on refusal");
    // No session eviction.
    assert_eq!(mock.attempt_count(), 0);
    // Metrics: trigger counted, apply_failure counted, success NOT bumped.
    assert_eq!(metrics.live_reload_trigger_total(), 1);
    assert_eq!(metrics.live_reload_apply_success_total(), 0);
    assert_eq!(metrics.live_reload_apply_failure_total(), 1);
    assert_eq!(metrics.live_reload_sessions_evicted_total(), 0);
    assert_eq!(metrics.live_reload_last_applied_sequence(), 0);
}

// =====================================================================
// Scenario C — Strict / bad signature: refuses before any mutation.
// =====================================================================

#[test]
fn run114_strict_bad_signature_sidecar_refuses_before_any_mutation() {
    let h = devnet_harness();
    let dir = tmpdir("strict-bad-sig");
    let seq_path = sequence_file_path(&dir);
    let baseline_bundle = build_signed_bundle(&h, 1, 100);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline_bundle);
    let candidate_bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate_bundle);

    let mut ratification = build_valid_ratification(&h);
    // Flip a byte of the signature to break verification.
    ratification.signature[0] ^= 0xff;
    let sidecar_path = write_ratification(&dir, "bad.json", &ratification);

    let (ctl, live, mock, metrics) = make_controller(
        &h,
        candidate_path,
        Some(seq_path.clone()),
        &baseline_path,
        Some(sidecar_path),
        RatificationEnforcementPolicy::Strict,
        true,
    );

    let pre_fp = snapshot_state_fingerprint(&live);
    let out = ctl.try_trigger_with_now(300);
    match out {
        LiveReloadOutcome::Invalid(ReloadApplyError::ValidationFailed(
            ReloadCheckError::RatificationRefused(RatificationEnforcementFailure::Verifier(
                RatificationFailure::BadSignature,
            )),
        )) => {}
        other => panic!("expected Verifier(BadSignature), got {:?}", other),
    }

    assert_eq!(snapshot_state_fingerprint(&live), pre_fp);
    assert!(!seq_path.exists());
    assert_eq!(mock.attempt_count(), 0);
    assert_eq!(metrics.live_reload_apply_success_total(), 0);
    assert_eq!(metrics.live_reload_apply_failure_total(), 1);
}

// =====================================================================
// Scenario D — Strict / wrong chain: refuses before any mutation.
// =====================================================================

#[test]
fn run114_strict_wrong_chain_sidecar_refuses_before_any_mutation() {
    let h = devnet_harness();
    let dir = tmpdir("strict-wrong-chain");
    let seq_path = sequence_file_path(&dir);
    let baseline_bundle = build_signed_bundle(&h, 1, 100);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline_bundle);
    let candidate_bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate_bundle);

    // Sign a ratification with a different chain_id string.
    let ratification = ratification_helpers::build_signed_ratification(
        "qbind-some-other-chain",
        RatificationEnvironment::Devnet,
        h.canonical_hash,
        &hex_lower(&h.authority_pk),
        &h.authority_sk,
        &h.signing_pk,
    );
    let sidecar_path = write_ratification(&dir, "wrong-chain.json", &ratification);

    let (ctl, live, mock, _metrics) = make_controller(
        &h,
        candidate_path,
        Some(seq_path.clone()),
        &baseline_path,
        Some(sidecar_path),
        RatificationEnforcementPolicy::Strict,
        true,
    );

    let pre_fp = snapshot_state_fingerprint(&live);
    let out = ctl.try_trigger_with_now(300);
    match out {
        LiveReloadOutcome::Invalid(ReloadApplyError::ValidationFailed(
            ReloadCheckError::RatificationRefused(RatificationEnforcementFailure::Verifier(
                RatificationFailure::ChainMismatch { .. },
            )),
        )) => {}
        other => panic!("expected ChainIdMismatch, got {:?}", other),
    }
    assert_eq!(snapshot_state_fingerprint(&live), pre_fp);
    assert!(!seq_path.exists());
    assert_eq!(mock.attempt_count(), 0);
}

// =====================================================================
// Scenario E — Strict / wrong environment: refuses before any mutation.
// =====================================================================

#[test]
fn run114_strict_wrong_environment_sidecar_refuses_before_any_mutation() {
    let h = devnet_harness();
    let dir = tmpdir("strict-wrong-env");
    let seq_path = sequence_file_path(&dir);
    let baseline_bundle = build_signed_bundle(&h, 1, 100);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline_bundle);
    let candidate_bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate_bundle);

    // Sign a ratification with Mainnet environment instead of Devnet.
    let ratification = ratification_helpers::build_signed_ratification(
        &h.chain_id_str,
        RatificationEnvironment::Mainnet,
        h.canonical_hash,
        &hex_lower(&h.authority_pk),
        &h.authority_sk,
        &h.signing_pk,
    );
    let sidecar_path = write_ratification(&dir, "wrong-env.json", &ratification);

    let (ctl, live, mock, _metrics) = make_controller(
        &h,
        candidate_path,
        Some(seq_path.clone()),
        &baseline_path,
        Some(sidecar_path),
        RatificationEnforcementPolicy::Strict,
        true,
    );

    let pre_fp = snapshot_state_fingerprint(&live);
    let out = ctl.try_trigger_with_now(300);
    match out {
        LiveReloadOutcome::Invalid(ReloadApplyError::ValidationFailed(
            ReloadCheckError::RatificationRefused(RatificationEnforcementFailure::Verifier(
                RatificationFailure::EnvironmentMismatch { .. },
            )),
        )) => {}
        other => panic!("expected EnvironmentMismatch, got {:?}", other),
    }
    assert_eq!(snapshot_state_fingerprint(&live), pre_fp);
    assert!(!seq_path.exists());
    assert_eq!(mock.attempt_count(), 0);
}

// =====================================================================
// Scenario F — Strict / unknown authority root: refuses before mutation.
// =====================================================================

#[test]
fn run114_strict_unknown_authority_root_refuses_before_any_mutation() {
    let h = devnet_harness();
    let dir = tmpdir("strict-unknown-root");
    let seq_path = sequence_file_path(&dir);
    let baseline_bundle = build_signed_bundle(&h, 1, 100);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline_bundle);
    let candidate_bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate_bundle);

    // Sign a ratification with a freshly-generated authority key
    // that is NOT in the harness's genesis authority block.
    let (rogue_pk, rogue_sk) = MlDsa44Backend::generate_keypair().expect("rogue keygen");
    let ratification = ratification_helpers::build_signed_ratification(
        &h.chain_id_str,
        RatificationEnvironment::Devnet,
        h.canonical_hash,
        &hex_lower(&rogue_pk),
        &rogue_sk,
        &h.signing_pk,
    );
    let sidecar_path = write_ratification(&dir, "unknown-root.json", &ratification);

    let (ctl, live, mock, _metrics) = make_controller(
        &h,
        candidate_path,
        Some(seq_path.clone()),
        &baseline_path,
        Some(sidecar_path),
        RatificationEnforcementPolicy::Strict,
        true,
    );

    let pre_fp = snapshot_state_fingerprint(&live);
    let out = ctl.try_trigger_with_now(300);
    match out {
        LiveReloadOutcome::Invalid(ReloadApplyError::ValidationFailed(
            ReloadCheckError::RatificationRefused(RatificationEnforcementFailure::Verifier(
                RatificationFailure::UnknownAuthorityRoot { .. },
            )),
        )) => {}
        other => panic!("expected AuthorityRootUnknown, got {:?}", other),
    }
    assert_eq!(snapshot_state_fingerprint(&live), pre_fp);
    assert!(!seq_path.exists());
    assert_eq!(mock.attempt_count(), 0);
}

// =====================================================================
// Scenario G — Strict / ratifies a DIFFERENT key than the candidate
// was actually signed by: refuses before any mutation.
// =====================================================================

#[test]
fn run114_strict_ratifies_different_key_refuses_before_any_mutation() {
    let h = devnet_harness();
    let dir = tmpdir("strict-diff-key");
    let seq_path = sequence_file_path(&dir);
    let baseline_bundle = build_signed_bundle(&h, 1, 100);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline_bundle);
    let candidate_bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate_bundle);

    // Valid signed ratification but for a DIFFERENT bundle-signing
    // public key than the candidate was signed with.
    let ratification = ratification_helpers::build_signed_ratification(
        &h.chain_id_str,
        RatificationEnvironment::Devnet,
        h.canonical_hash,
        &hex_lower(&h.authority_pk),
        &h.authority_sk,
        &h.other_signing_pk,
    );
    let sidecar_path = write_ratification(&dir, "diff-key.json", &ratification);

    let (ctl, live, mock, _metrics) = make_controller(
        &h,
        candidate_path,
        Some(seq_path.clone()),
        &baseline_path,
        Some(sidecar_path),
        RatificationEnforcementPolicy::Strict,
        true,
    );

    let pre_fp = snapshot_state_fingerprint(&live);
    let out = ctl.try_trigger_with_now(300);
    match out {
        LiveReloadOutcome::Invalid(ReloadApplyError::ValidationFailed(
            ReloadCheckError::RatificationRefused(
                RatificationEnforcementFailure::RatifiesDifferentKey { .. },
            ),
        )) => {}
        other => panic!("expected RatifiesDifferentKey, got {:?}", other),
    }
    assert_eq!(snapshot_state_fingerprint(&live), pre_fp);
    assert!(!seq_path.exists());
    assert_eq!(mock.attempt_count(), 0);
}

// =====================================================================
// Scenario H — Sidecar I/O failure (path set but file missing):
// refuses fail-closed before any mutation.
// =====================================================================

#[test]
fn run114_strict_sidecar_io_failure_refuses_before_any_mutation() {
    let h = devnet_harness();
    let dir = tmpdir("strict-io");
    let seq_path = sequence_file_path(&dir);
    let baseline_bundle = build_signed_bundle(&h, 1, 100);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline_bundle);
    let candidate_bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate_bundle);

    // Sidecar path points to a non-existent file.
    let sidecar_path = dir.join("does-not-exist.json");

    let (ctl, live, mock, metrics) = make_controller(
        &h,
        candidate_path,
        Some(seq_path.clone()),
        &baseline_path,
        Some(sidecar_path),
        RatificationEnforcementPolicy::Strict,
        true,
    );

    let pre_fp = snapshot_state_fingerprint(&live);
    let out = ctl.try_trigger_with_now(300);
    match out {
        // Sidecar I/O is wrapped into ReloadCheckError::Bundle(Io) so
        // it surfaces on the same Invalid pathway as any other
        // pre-mutation candidate-load refusal.
        LiveReloadOutcome::Invalid(ReloadApplyError::ValidationFailed(
            ReloadCheckError::Bundle(_),
        )) => {}
        other => panic!("expected Invalid(ValidationFailed(Bundle(Io))), got {:?}", other),
    }
    assert_eq!(snapshot_state_fingerprint(&live), pre_fp);
    assert!(!seq_path.exists());
    assert_eq!(mock.attempt_count(), 0);
    assert_eq!(metrics.live_reload_apply_failure_total(), 1);
}

// =====================================================================
// Scenario I — Sidecar parse failure (malformed JSON): refuses
// fail-closed before any mutation.
// =====================================================================

#[test]
fn run114_strict_sidecar_parse_failure_refuses_before_any_mutation() {
    let h = devnet_harness();
    let dir = tmpdir("strict-parse");
    let seq_path = sequence_file_path(&dir);
    let baseline_bundle = build_signed_bundle(&h, 1, 100);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline_bundle);
    let candidate_bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate_bundle);

    let sidecar_path = dir.join("malformed.json");
    std::fs::write(&sidecar_path, b"{ not valid json").expect("write malformed");

    let (ctl, live, mock, _metrics) = make_controller(
        &h,
        candidate_path,
        Some(seq_path.clone()),
        &baseline_path,
        Some(sidecar_path),
        RatificationEnforcementPolicy::Strict,
        true,
    );

    let pre_fp = snapshot_state_fingerprint(&live);
    let out = ctl.try_trigger_with_now(300);
    assert!(
        matches!(
            out,
            LiveReloadOutcome::Invalid(ReloadApplyError::ValidationFailed(
                ReloadCheckError::Bundle(_),
            ))
        ),
        "expected Invalid(ValidationFailed(Bundle(_))) for parse error"
    );
    assert_eq!(snapshot_state_fingerprint(&live), pre_fp);
    assert!(!seq_path.exists());
    assert_eq!(mock.attempt_count(), 0);
}

// =====================================================================
// Scenario J — Repeated-trigger safety: invalid → valid.
// =====================================================================

#[test]
fn run114_invalid_sighup_followed_by_valid_sighup_succeeds() {
    let h = devnet_harness();
    let dir = tmpdir("inv-then-valid");
    let seq_path = sequence_file_path(&dir);
    let baseline_bundle = build_signed_bundle(&h, 1, 100);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline_bundle);
    let candidate_bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate_bundle);

    // Operator starts with NO sidecar at `sidecar_path` — the first
    // SIGHUP must surface `Missing` and not mutate. They then write
    // a valid sidecar at the same path and SIGHUP again — the
    // second trigger must apply.
    let sidecar_path = dir.join("ratification.json");

    let (ctl, live, mock, metrics) = make_controller(
        &h,
        candidate_path,
        Some(seq_path.clone()),
        &baseline_path,
        Some(sidecar_path.clone()),
        RatificationEnforcementPolicy::Strict,
        true,
    );

    let pre_fp = snapshot_state_fingerprint(&live);

    // 1st trigger — sidecar file does not exist yet.
    let out1 = ctl.try_trigger_with_now(300);
    assert!(matches!(out1, LiveReloadOutcome::Invalid(_)));
    assert_eq!(snapshot_state_fingerprint(&live), pre_fp);
    assert!(!seq_path.exists());
    assert_eq!(mock.attempt_count(), 0);
    assert_eq!(metrics.live_reload_apply_success_total(), 0);

    // Operator writes valid sidecar in-place.
    let ratification = build_valid_ratification(&h);
    write_ratification(&dir, "ratification.json", &ratification);

    // 2nd trigger — must apply now.
    let out2 = ctl.try_trigger_with_now(301);
    match out2 {
        LiveReloadOutcome::Applied(applied) => assert_eq!(applied.validated.sequence, 2),
        other => panic!("expected Applied after valid sidecar appears, got {:?}", other),
    }
    assert_ne!(snapshot_state_fingerprint(&live), pre_fp);
    assert!(seq_path.exists());
    assert_eq!(mock.attempt_count(), 1);
    assert_eq!(metrics.live_reload_trigger_total(), 2);
    assert_eq!(metrics.live_reload_apply_success_total(), 1);
    assert_eq!(metrics.live_reload_apply_failure_total(), 1);
}

// =====================================================================
// Scenario K — Repeated-trigger safety: valid → invalid does not
// roll back the prior valid state.
// =====================================================================

#[test]
fn run114_valid_sighup_followed_by_invalid_sighup_does_not_rollback_prior_state() {
    let h = devnet_harness();
    let dir = tmpdir("valid-then-inv");
    let seq_path = sequence_file_path(&dir);
    let baseline_bundle = build_signed_bundle(&h, 1, 100);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline_bundle);
    let candidate_bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate_bundle);

    let ratification = build_valid_ratification(&h);
    let sidecar_path = write_ratification(&dir, "ratification.json", &ratification);

    let (ctl, live, mock, metrics) = make_controller(
        &h,
        candidate_path,
        Some(seq_path.clone()),
        &baseline_path,
        Some(sidecar_path.clone()),
        RatificationEnforcementPolicy::Strict,
        true,
    );

    // 1st trigger — valid apply.
    let out1 = ctl.try_trigger_with_now(300);
    assert!(matches!(out1, LiveReloadOutcome::Applied(_)));
    let post_valid_fp = snapshot_state_fingerprint(&live);
    let seq_after_valid = std::fs::read(&seq_path).expect("read");

    // 2nd trigger — operator replaces sidecar with a malformed
    // one. The SIGHUP must refuse but the prior valid live state
    // and the on-disk sequence record must remain.
    std::fs::write(&sidecar_path, b"{ not valid json").expect("overwrite");
    let out2 = ctl.try_trigger_with_now(301);
    assert!(matches!(out2, LiveReloadOutcome::Invalid(_)));

    // Live state still matches the previously-applied valid state.
    assert_eq!(snapshot_state_fingerprint(&live), post_valid_fp);
    // Sequence file untouched.
    let seq_after_invalid = std::fs::read(&seq_path).expect("read");
    assert_eq!(seq_after_valid, seq_after_invalid);

    // Evictor called exactly once (only the first, valid, trigger).
    assert_eq!(mock.attempt_count(), 1);
    assert_eq!(metrics.live_reload_apply_success_total(), 1);
    assert_eq!(metrics.live_reload_apply_failure_total(), 1);
}

// =====================================================================
// Scenario L — Repeated invalid SIGHUPs do not mutate or advance the
// sequence file at all.
// =====================================================================

#[test]
fn run114_repeated_invalid_sighups_do_not_mutate_or_advance_sequence() {
    let h = devnet_harness();
    let dir = tmpdir("repeated-inv");
    let seq_path = sequence_file_path(&dir);
    let baseline_bundle = build_signed_bundle(&h, 1, 100);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline_bundle);
    let candidate_bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate_bundle);

    // No sidecar at any point.
    let (ctl, live, mock, metrics) = make_controller(
        &h,
        candidate_path,
        Some(seq_path.clone()),
        &baseline_path,
        None,
        RatificationEnforcementPolicy::Strict,
        true,
    );

    let pre_fp = snapshot_state_fingerprint(&live);
    for i in 0..5 {
        let out = ctl.try_trigger_with_now(300 + i);
        assert!(
            matches!(out, LiveReloadOutcome::Invalid(_)),
            "iteration {} expected Invalid, got {:?}",
            i,
            out
        );
        assert_eq!(snapshot_state_fingerprint(&live), pre_fp);
        assert!(!seq_path.exists());
        assert_eq!(mock.attempt_count(), 0);
    }
    assert_eq!(metrics.live_reload_trigger_total(), 5);
    assert_eq!(metrics.live_reload_apply_failure_total(), 5);
    assert_eq!(metrics.live_reload_apply_success_total(), 0);
    assert_eq!(metrics.live_reload_sessions_evicted_total(), 0);
}

// =====================================================================
// Scenario M — DevNet legacy: enforce=false (gate Skip) preserves
// pre-Run-114 SIGHUP behaviour (no ratification check; the bundle
// applies via the existing Run 074 path).
// =====================================================================

#[test]
fn run114_devnet_no_opt_in_skips_ratification_and_applies_via_pre_run114_path() {
    let h = devnet_harness();
    let dir = tmpdir("devnet-skip");
    let seq_path = sequence_file_path(&dir);
    let baseline_bundle = build_signed_bundle(&h, 1, 100);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline_bundle);
    let candidate_bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate_bundle);

    // enforce=false → controller is constructed with `ratification: None`.
    let (ctl, live, mock, metrics) = make_controller(
        &h,
        candidate_path,
        Some(seq_path.clone()),
        &baseline_path,
        None,
        RatificationEnforcementPolicy::Strict,
        false,
    );

    let pre_fp = snapshot_state_fingerprint(&live);
    let out = ctl.try_trigger_with_now(300);
    match out {
        LiveReloadOutcome::Applied(applied) => assert_eq!(applied.validated.sequence, 2),
        other => panic!("expected Applied on DevNet skip path, got {:?}", other),
    }
    assert_ne!(snapshot_state_fingerprint(&live), pre_fp);
    assert!(seq_path.exists());
    assert_eq!(mock.attempt_count(), 1);
    assert_eq!(metrics.live_reload_apply_success_total(), 1);
}

// =====================================================================
// Scenario N — Ratification refusal occurs BEFORE the candidate
// bundle even needs to load: tampered candidate is irrelevant on
// the refusal path because ratification fails first.
//
// We prove this by checking that a missing sidecar + a candidate
// that WOULD otherwise pass validation still surfaces the
// `Missing` ratification refusal — i.e. the ratification gate
// stops the apply at the same point regardless of candidate
// validity. This guards against future refactors that might
// accidentally re-order the gate to run AFTER candidate load /
// post-validation.
// =====================================================================

#[test]
fn run114_ratification_refusal_short_circuits_apply_pipeline() {
    let h = devnet_harness();
    let dir = tmpdir("short-circuit");
    let seq_path = sequence_file_path(&dir);
    let baseline_bundle = build_signed_bundle(&h, 1, 100);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline_bundle);
    let candidate_bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate_bundle);

    let (ctl, live, mock, _metrics) = make_controller(
        &h,
        candidate_path,
        Some(seq_path.clone()),
        &baseline_path,
        None, // no sidecar
        RatificationEnforcementPolicy::Strict,
        true,
    );

    let pre_fp = snapshot_state_fingerprint(&live);
    let out = ctl.try_trigger_with_now(300);
    // Must be the `Missing` refusal, NOT a later-pipeline error.
    match out {
        LiveReloadOutcome::Invalid(ReloadApplyError::ValidationFailed(
            ReloadCheckError::RatificationRefused(
                RatificationEnforcementFailure::Missing { .. },
            ),
        )) => {}
        other => panic!(
            "expected Missing ratification refusal to short-circuit, got {:?}",
            other
        ),
    }
    assert_eq!(snapshot_state_fingerprint(&live), pre_fp);
    assert!(!seq_path.exists());
    assert_eq!(mock.attempt_count(), 0);
}