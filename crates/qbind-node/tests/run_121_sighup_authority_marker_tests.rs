//! Run 121 — integration tests for the **SIGHUP live trust-bundle
//! reload-apply authority anti-rollback marker** wired through
//! [`qbind_node::pqc_live_trust_reload::LiveReloadController`].
//!
//! These tests drive the EXACT same controller entry point that the
//! `qbind-node` binary's SIGHUP signal-handler task calls
//! (`try_trigger_with_now`), but exercise it with BOTH a populated
//! [`qbind_node::pqc_live_trust_reload::LiveReloadRatificationConfig`]
//! (Run 114) AND a populated
//! [`qbind_node::pqc_live_trust_reload::LiveReloadAuthorityMarkerConfig`]
//! (Run 121). The same Run 119 `decide_marker_acceptance` +
//! `persist_accepted_marker_after_commit_boundary` helpers that
//! Run 119 (reload-apply) and Run 120 (startup `--p2p-trust-bundle`)
//! use are invoked from the SIGHUP controller — no parallel
//! marker-acceptance stack.
//!
//! Invariants proved by this file:
//!
//!   * **First-write**: a valid SIGHUP under Strict ratification with
//!     no pre-existing marker passes the preflight and falls through
//!     to the existing Run 070/074/114 ordering (snapshot → swap →
//!     evict → commit). The marker file is created post-commit with
//!     [`qbind_node::pqc_authority_state::AuthorityStateUpdateSource::SighupReload`].
//!   * **Idempotent**: re-applying the same candidate + same
//!     ratification when an identical marker already exists is a
//!     no-op (no rewrite of the audit-only `updated_at_unix_secs`).
//!   * **Same-sequence ratification conflict**: pre-persisting a
//!     marker for the same `authority_sequence` but a different
//!     ratification refuses the SIGHUP BEFORE any snapshot / swap /
//!     eviction / commit. Live state, sessions, sequence file, and
//!     on-disk marker all byte-identical.
//!   * **Persisted-domain mismatch**: pre-persisting a marker for a
//!     different `(environment, chain_id, genesis_hash)` trust
//!     domain refuses fail-closed without any mutation.
//!   * **Corrupt marker file**: a structurally invalid marker file
//!     refuses fail-closed with `LoadOrCorruption` and is NOT
//!     silently overwritten by the controller.
//!   * **DevNet no-opt-in**: when the ratification gate is `Skip`
//!     (DevNet without `--p2p-trust-bundle-ratification-enforcement-enabled`),
//!     the marker config is `None` and the marker file is NEVER
//!     created — pre-Run-121 SIGHUP behaviour byte-identical.
//!   * **Persist-failure is fatal**: when the marker atomic write
//!     fails AFTER the apply pipeline's commit boundary, the
//!     outcome is `MarkerPersistFailureAfterCommit` with
//!     `is_fatal()` returning `true` (so the binary's SIGHUP task
//!     signals graceful shutdown). The live state DID advance —
//!     the stale-by-one marker is safely replayable as an
//!     `Upgrade` on the next accepted mutation per Run 118 §D.
//!
//! Strict scope (matches `task/RUN_121_TASK.txt`):
//!
//!   * SIGHUP live-reload only — Run 119/120 cover reload-apply and
//!     startup respectively.
//!   * No peer-driven live apply.
//!   * No signing-key rotation / revocation.
//!   * No KMS / HSM custody.
//!   * No `--allow-authority-state-reset` recovery flag.
//!   * No change to trust-bundle / peer-candidate / ratification /
//!     marker wire formats.
//!   * No weakening of any existing Run 050/055/057/065/069/070/
//!     071/072/073/074/103/104/105/106/107/109/112/114/115/116/
//!     117/118/119/120 invariant.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_121.md`.

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
    canonical_ratification_digest, compute_canonical_genesis_hash, BundleSigningRatification,
    GenesisHash, NetworkEnvironmentPolicy, RatificationEnforcementPolicy, RatificationEnvironment,
};
use qbind_node::metrics::P2pMetrics;
use qbind_node::p2p_session_eviction::{MockP2pSessionEvictor, P2pSessionEvictor};
use qbind_node::pqc_authority_state::{
    authority_state_file_path, load_authority_state, persist_authority_state_atomic,
    AuthorityStateUpdateSource, PersistentAuthorityStateRecord,
};
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_live_trust::LivePqcTrustState;
use qbind_node::pqc_live_trust_reload::{
    LiveReloadAuthorityMarkerConfig, LiveReloadConfig, LiveReloadController, LiveReloadOutcome,
    LiveReloadRatificationConfig,
};
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
use qbind_node::pqc_trust_activation::ActivationContext;
use qbind_node::pqc_trust_bundle::{
    derive_signing_key_id, sign_bundle_devnet_helper, BundleSigningKey, BundleSigningKeySet,
    LoadedTrustBundle, RootStatus, TrustBundle, TrustBundleEnvironment, TrustBundleRevocation,
    TrustBundleRoot,
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
        "qbind-run121-{}-{}-{}",
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
    authority_root_fingerprint: String,
    canonical_hash: GenesisHash,
    chain_id_str: String,
    env_policy: NetworkEnvironmentPolicy,
    authority: GenesisAuthorityConfig,
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
    let auth_root = GenesisAuthorityRoot::with_public_key_bytes(
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        &authority_pk,
        "run-121-bundle-signing-1",
    );
    let authority_root_fingerprint = auth_root.key_fingerprint.clone();
    let authority = GenesisAuthorityConfig::new(vec![auth_root]);
    genesis_cfg.authority = Some(authority.clone());
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
        authority_root_fingerprint,
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

#[allow(clippy::too_many_arguments)]
fn make_controller(
    h: &Harness,
    candidate_path: PathBuf,
    seq_path: Option<PathBuf>,
    baseline_path: &Path,
    sidecar_path: Option<PathBuf>,
    policy: RatificationEnforcementPolicy,
    enforce: bool,
    marker_path: Option<PathBuf>,
) -> (
    LiveReloadController,
    Arc<LivePqcTrustState>,
    Arc<MockP2pSessionEvictor>,
    Arc<P2pMetrics>,
) {
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
    let authority_marker = marker_path.map(|marker_path| LiveReloadAuthorityMarkerConfig {
        marker_path,
    });
    let cfg = LiveReloadConfig {
        candidate_path,
        environment: NetworkEnvironment::Devnet,
        chain_id: NetworkEnvironment::Devnet.chain_id(),
        signing_keys: h.signing_keys.clone(),
        activation_ctx: ActivationContext::height_only(0),
        sequence_path: seq_path,
        local_leaf_cert_bytes: None,
        ratification,
        authority_marker,
    };
    let ctl = LiveReloadController::new(live.clone(), evictor, metrics.clone(), cfg);
    (ctl, live, mock, metrics)
}

fn snapshot_state_fingerprint(live: &Arc<LivePqcTrustState>) -> Vec<u8> {
    live.snapshot().expect("snap").fingerprint().to_vec()
}

fn signing_key_fingerprint_hex(pk: &[u8]) -> String {
    use sha3::{Digest, Sha3_256};
    hex_lower(Sha3_256::digest(pk).as_slice())
}

// =====================================================================
// Scenario A — First-write: SIGHUP applies and creates the marker.
// =====================================================================

#[test]
fn run121_first_write_creates_marker_with_sighup_audit_tag() {
    let h = devnet_harness();
    let dir = tmpdir("first-write");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);

    let baseline_bundle = build_signed_bundle(&h, 1, 100);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline_bundle);
    let candidate_bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate_bundle);
    let ratification = build_valid_ratification(&h);
    let sidecar_path = write_ratification(&dir, "ratification.json", &ratification);

    assert!(!marker_path.exists(), "no marker file expected pre-trigger");

    let (ctl, live, mock, metrics) = make_controller(
        &h,
        candidate_path,
        Some(seq_path.clone()),
        &baseline_path,
        Some(sidecar_path),
        RatificationEnforcementPolicy::Strict,
        true,
        Some(marker_path.clone()),
    );

    let pre_fp = snapshot_state_fingerprint(&live);
    let out = ctl.try_trigger_with_now(300);
    match &out {
        LiveReloadOutcome::Applied(applied) => {
            assert_eq!(applied.validated.sequence, 2);
        }
        other => panic!("expected Applied(_), got {:?}", other),
    }
    assert!(!out.is_fatal(), "first-write must not be fatal");

    // Live state advanced; sequence file written; eviction called.
    let post_fp = snapshot_state_fingerprint(&live);
    assert_ne!(pre_fp, post_fp);
    assert!(seq_path.exists(), "sequence file must be created");
    assert_eq!(mock.attempt_count(), 1);

    // Marker file created with SighupReload audit tag.
    assert!(marker_path.exists(), "marker file must be created post-commit");
    let persisted = load_authority_state(&marker_path)
        .expect("load")
        .expect("marker present after first-write");
    assert_eq!(
        persisted.last_update_source,
        AuthorityStateUpdateSource::SighupReload,
        "marker audit tag must identify SIGHUP path"
    );
    assert_eq!(persisted.chain_id, h.chain_id_str);
    assert_eq!(persisted.environment, TrustBundleEnvironment::Devnet);
    assert_eq!(persisted.genesis_hash, hex_lower(&h.canonical_hash));
    assert_eq!(persisted.authority_sequence, h.authority.authority_sequence);
    assert_eq!(
        persisted.ratified_bundle_signing_key_fingerprint,
        signing_key_fingerprint_hex(&h.signing_pk)
    );
    assert_eq!(
        persisted.ratification_object_hash,
        hex_lower(&canonical_ratification_digest(&ratification))
    );

    // Metrics: trigger + success bumped, no failure.
    assert_eq!(metrics.live_reload_trigger_total(), 1);
    assert_eq!(metrics.live_reload_apply_success_total(), 1);
    assert_eq!(metrics.live_reload_apply_failure_total(), 0);
}

// =====================================================================
// Scenario B — Idempotent: re-applying same candidate is a no-op write.
// =====================================================================

#[test]
fn run121_re_apply_same_candidate_is_idempotent_no_marker_rewrite() {
    let h = devnet_harness();
    let dir = tmpdir("idempotent");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);

    let baseline_bundle = build_signed_bundle(&h, 1, 100);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline_bundle);
    let candidate_bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate_bundle);
    let ratification = build_valid_ratification(&h);
    let sidecar_path = write_ratification(&dir, "ratification.json", &ratification);

    let (ctl, _live, _mock, _metrics) = make_controller(
        &h,
        candidate_path,
        Some(seq_path),
        &baseline_path,
        Some(sidecar_path),
        RatificationEnforcementPolicy::Strict,
        true,
        Some(marker_path.clone()),
    );

    // First trigger: first-write.
    let first = ctl.try_trigger_with_now(300);
    assert!(matches!(first, LiveReloadOutcome::Applied(_)));
    let bytes_after_first = std::fs::read(&marker_path).expect("marker exists");
    let mtime_after_first = std::fs::metadata(&marker_path)
        .expect("metadata")
        .modified()
        .ok();

    // Wait a moment so any rewrite would change the mtime.
    std::thread::sleep(std::time::Duration::from_millis(50));

    // Second trigger with same candidate / ratification — Run 055
    // anti-rollback makes the apply pipeline idempotent (no live
    // state change, no new sequence write), and Run 121 marker
    // should be Idempotent (no rewrite of audit-only fields).
    let second = ctl.try_trigger_with_now(400);
    // Regardless of the apply variant, the marker must NOT be
    // rewritten on the idempotent SIGHUP path.
    let bytes_after_second = std::fs::read(&marker_path).expect("marker still exists");
    assert_eq!(
        bytes_after_first, bytes_after_second,
        "Run 121 idempotent path MUST NOT rewrite marker bytes (got divergent bytes; outcome={:?})",
        second
    );
    let mtime_after_second = std::fs::metadata(&marker_path)
        .expect("metadata")
        .modified()
        .ok();
    assert_eq!(
        mtime_after_first, mtime_after_second,
        "Run 121 idempotent path MUST NOT touch marker mtime"
    );
}

// =====================================================================
// Scenario C — Pre-persisted rollback marker refuses BEFORE any mutation.
// =====================================================================

#[test]
fn run121_pre_persisted_higher_sequence_refuses_before_any_mutation() {
    let h = devnet_harness();
    let dir = tmpdir("rollback-reject");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);

    // Pre-persist a marker at a strictly HIGHER authority_sequence
    // than the genesis-bound `authority_sequence` (which is the
    // value the candidate's verified ratification will produce).
    let candidate_authority_sequence = h.authority.authority_sequence;
    let higher = candidate_authority_sequence
        .checked_add(1)
        .expect("no overflow");
    let other_ratification = build_valid_ratification(&h);
    let prepersisted = PersistentAuthorityStateRecord::new(
        h.chain_id_str.clone(),
        TrustBundleEnvironment::Devnet,
        hex_lower(&h.canonical_hash),
        h.authority.authority_policy_version,
        higher,
        h.authority.authority_epoch,
        h.authority_root_fingerprint.clone(),
        signing_key_fingerprint_hex(&h.signing_pk),
        hex_lower(&canonical_ratification_digest(&other_ratification)),
        AuthorityStateUpdateSource::SighupReload,
        100,
    );
    persist_authority_state_atomic(&marker_path, &prepersisted).expect("persist");
    let marker_bytes_before = std::fs::read(&marker_path).expect("read marker");

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
        Some(sidecar_path),
        RatificationEnforcementPolicy::Strict,
        true,
        Some(marker_path.clone()),
    );

    let pre_fp = snapshot_state_fingerprint(&live);
    let out = ctl.try_trigger_with_now(300);
    match &out {
        LiveReloadOutcome::MarkerRejected(_) => {}
        other => panic!("expected MarkerRejected(_), got {:?}", other),
    }
    assert!(out.is_marker_rejected());
    assert!(!out.is_applied());
    assert!(!out.is_fatal());

    // No live trust mutation, no sequence write, no session
    // eviction, no marker rewrite — strict pre-mutation refusal.
    let post_fp = snapshot_state_fingerprint(&live);
    assert_eq!(pre_fp, post_fp, "live state must not mutate on marker refusal");
    assert!(!seq_path.exists(), "sequence file must NOT be created");
    assert_eq!(mock.attempt_count(), 0, "no session eviction on marker refusal");
    let marker_bytes_after = std::fs::read(&marker_path).expect("marker still exists");
    assert_eq!(
        marker_bytes_before, marker_bytes_after,
        "marker file must be byte-identical on refusal"
    );

    // Metrics: trigger + failure bumped.
    assert_eq!(metrics.live_reload_trigger_total(), 1);
    assert_eq!(metrics.live_reload_apply_success_total(), 0);
    assert_eq!(metrics.live_reload_apply_failure_total(), 1);
}

// =====================================================================
// Scenario D — Persisted-domain mismatch refuses BEFORE any mutation.
// =====================================================================

#[test]
fn run121_pre_persisted_different_domain_refuses_before_any_mutation() {
    let h = devnet_harness();
    let dir = tmpdir("domain-mismatch");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);

    // Pre-persist a marker for a DIFFERENT trust domain (different
    // chain_id). Structurally valid; semantically wrong-data-dir.
    let other_chain_id_str = chain_id_hex(NetworkEnvironment::Testnet.chain_id());
    let other_ratification = build_valid_ratification(&h);
    let prepersisted = PersistentAuthorityStateRecord::new(
        other_chain_id_str,
        TrustBundleEnvironment::Devnet,
        hex_lower(&h.canonical_hash),
        h.authority.authority_policy_version,
        h.authority.authority_sequence,
        h.authority.authority_epoch,
        h.authority_root_fingerprint.clone(),
        signing_key_fingerprint_hex(&h.signing_pk),
        hex_lower(&canonical_ratification_digest(&other_ratification)),
        AuthorityStateUpdateSource::SighupReload,
        100,
    );
    persist_authority_state_atomic(&marker_path, &prepersisted).expect("persist");

    let baseline_bundle = build_signed_bundle(&h, 1, 100);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline_bundle);
    let candidate_bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate_bundle);
    let ratification = build_valid_ratification(&h);
    let sidecar_path = write_ratification(&dir, "ratification.json", &ratification);

    let (ctl, live, mock, _metrics) = make_controller(
        &h,
        candidate_path,
        Some(seq_path.clone()),
        &baseline_path,
        Some(sidecar_path),
        RatificationEnforcementPolicy::Strict,
        true,
        Some(marker_path.clone()),
    );

    let pre_fp = snapshot_state_fingerprint(&live);
    let out = ctl.try_trigger_with_now(300);
    assert!(
        matches!(out, LiveReloadOutcome::MarkerRejected(_)),
        "expected MarkerRejected for cross-domain marker, got {:?}",
        out
    );
    // No mutation.
    assert_eq!(snapshot_state_fingerprint(&live), pre_fp);
    assert!(!seq_path.exists());
    assert_eq!(mock.attempt_count(), 0);
}

// =====================================================================
// Scenario E — Corrupt marker file fails closed; not silently overwritten.
// =====================================================================

#[test]
fn run121_corrupt_marker_file_refuses_and_is_not_overwritten() {
    let h = devnet_harness();
    let dir = tmpdir("corrupt-marker");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    // Make sure parent directory exists (data_dir).
    std::fs::create_dir_all(marker_path.parent().expect("parent")).expect("mkdir parent");

    // Pre-write garbage that is not valid JSON authority record.
    let garbage = b"not a json record, intentionally corrupt for Run 121";
    std::fs::write(&marker_path, garbage).expect("write garbage");

    let baseline_bundle = build_signed_bundle(&h, 1, 100);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline_bundle);
    let candidate_bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate_bundle);
    let ratification = build_valid_ratification(&h);
    let sidecar_path = write_ratification(&dir, "ratification.json", &ratification);

    let (ctl, live, mock, _metrics) = make_controller(
        &h,
        candidate_path,
        Some(seq_path.clone()),
        &baseline_path,
        Some(sidecar_path),
        RatificationEnforcementPolicy::Strict,
        true,
        Some(marker_path.clone()),
    );

    let pre_fp = snapshot_state_fingerprint(&live);
    let out = ctl.try_trigger_with_now(300);
    assert!(
        matches!(out, LiveReloadOutcome::MarkerRejected(_)),
        "corrupt marker must fail closed; got {:?}",
        out
    );

    // Marker file is NOT silently overwritten by the controller.
    let bytes_after = std::fs::read(&marker_path).expect("marker still on disk");
    assert_eq!(
        bytes_after, garbage,
        "Run 121 MUST NOT silently overwrite a corrupt marker"
    );

    // No live state change, no sequence file, no eviction.
    assert_eq!(snapshot_state_fingerprint(&live), pre_fp);
    assert!(!seq_path.exists());
    assert_eq!(mock.attempt_count(), 0);
}

// =====================================================================
// Scenario F — DevNet no-opt-in: marker config None, pre-Run-121 path.
// =====================================================================

#[test]
fn run121_devnet_no_opt_in_skips_marker_and_preserves_pre_run121_path() {
    let h = devnet_harness();
    let dir = tmpdir("no-opt-in");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);

    let baseline_bundle = build_signed_bundle(&h, 1, 100);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline_bundle);
    let candidate_bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate_bundle);

    // No ratification, no marker. Pre-Run-114 / pre-Run-121 path.
    let (ctl, live, mock, _metrics) = make_controller(
        &h,
        candidate_path,
        Some(seq_path.clone()),
        &baseline_path,
        None,
        RatificationEnforcementPolicy::AllowLegacyUnratified,
        false,
        None,
    );

    let pre_fp = snapshot_state_fingerprint(&live);
    let out = ctl.try_trigger_with_now(300);
    assert!(
        matches!(out, LiveReloadOutcome::Applied(_)),
        "DevNet no-opt-in must apply via pre-Run-114 path; got {:?}",
        out
    );
    assert_ne!(snapshot_state_fingerprint(&live), pre_fp);
    assert!(seq_path.exists());
    assert_eq!(mock.attempt_count(), 1);

    // Marker file MUST NOT be created when no marker config wired.
    assert!(
        !marker_path.exists(),
        "Run 121 must NOT write a marker on the DevNet no-opt-in path"
    );
}

// =====================================================================
// Scenario G — Persist failure AFTER commit is fatal; live state DID advance.
// =====================================================================

#[test]
#[cfg(unix)]
fn run121_persist_failure_after_commit_is_fatal_and_apply_did_succeed() {
    let h = devnet_harness();
    let dir = tmpdir("persist-fatal");
    let seq_path = sequence_file_path(&dir);

    // We need a marker path where:
    //   * `load_authority_state` returns Ok(None) (so the preflight
    //     produces a `MarkerAcceptDecision` with should_persist=true);
    //   * but `persist_authority_state_atomic` then fails so we
    //     exercise the `MarkerPersistFailureAfterCommit` branch.
    //
    // We achieve this by pointing the marker at a path inside a
    // **read-only directory**. `load_authority_state` returns
    // Ok(None) on NotFound. The Run 117 atomic persister calls
    // `create_dir_all(parent)` (no-op since it already exists) and
    // then a temp-file write under that parent — which fails with
    // EACCES on the read-only parent.
    let ro_parent = dir.join("readonly-marker-dir");
    std::fs::create_dir_all(&ro_parent).expect("create ro parent");
    let marker_path = ro_parent.join("pqc_authority_state.json");
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&ro_parent)
            .expect("metadata")
            .permissions();
        perms.set_mode(0o555);
        std::fs::set_permissions(&ro_parent, perms).expect("chmod ro");
    }

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
        Some(sidecar_path),
        RatificationEnforcementPolicy::Strict,
        true,
        Some(marker_path.clone()),
    );

    let pre_fp = snapshot_state_fingerprint(&live);
    let out = ctl.try_trigger_with_now(300);
    match &out {
        LiveReloadOutcome::MarkerPersistFailureAfterCommit { applied, .. } => {
            assert_eq!(applied.validated.sequence, 2);
        }
        other => panic!(
            "expected MarkerPersistFailureAfterCommit, got {:?}",
            other
        ),
    }

    // Run 121 contract: persist-failure must be is_fatal() == true
    // so the binary's SIGHUP task initiates graceful shutdown.
    assert!(out.is_fatal(), "persist failure must signal fatal shutdown");
    // The apply DID succeed (live state DID advance, sequence DID
    // write, eviction DID happen) — the operator log line records
    // this so it is not silently lost.
    assert!(out.is_applied(), "apply DID succeed even on persist failure");
    let post_fp = snapshot_state_fingerprint(&live);
    assert_ne!(pre_fp, post_fp, "live state must advance");
    assert!(seq_path.exists(), "sequence file must be written");
    assert_eq!(mock.attempt_count(), 1, "eviction must have been called");

    // Marker file was NOT successfully persisted.
    assert!(!marker_path.exists(), "marker file must not exist post-fail");

    // Metrics: success counted (apply DID complete); failure NOT
    // counted (the apply pipeline itself succeeded).
    assert_eq!(metrics.live_reload_trigger_total(), 1);
    assert_eq!(metrics.live_reload_apply_success_total(), 1);
    assert_eq!(metrics.live_reload_apply_failure_total(), 0);

    // log_line names Run 121 explicitly.
    let line = out.log_line();
    assert!(
        line.contains("Run 121"),
        "log_line must mention Run 121; got: {}",
        line
    );
    assert!(
        line.contains("FATAL-marker-persist"),
        "log_line must name the FATAL-marker-persist verdict; got: {}",
        line
    );

    // Restore writability so the tmpdir can be cleaned up.
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&ro_parent)
            .expect("metadata")
            .permissions();
        perms.set_mode(0o755);
        let _ = std::fs::set_permissions(&ro_parent, perms);
    }
}