//! Run 138 — integration tests for the **v2 ratification + v2
//! authority-marker** wiring on the SIGHUP live trust-bundle reload
//! mutating surface.
//!
//! These tests drive the EXACT same controller entry point that the
//! `qbind-node` binary's SIGHUP signal-handler task calls
//! (`try_trigger_with_now`), but exercise it with a **v2** ratification
//! sidecar plus a populated
//! [`qbind_node::pqc_live_trust_reload::LiveReloadAuthorityMarkerConfig`].
//! The same Run 134/136 v2 marker helpers
//! ([`qbind_node::pqc_authority_marker_acceptance::decide_marker_acceptance_v2`]
//! and
//! [`qbind_node::pqc_authority_marker_acceptance::persist_accepted_v2_marker_after_commit_boundary`])
//! that Run 134 (reload-apply) and Run 136 (startup
//! `--p2p-trust-bundle`) use are invoked from the SIGHUP controller
//! via the Run 138 `preflight_sighup_v2_marker_decision` helper — no
//! parallel marker-acceptance stack.
//!
//! Acceptance scenarios (A1–A4) and rejection scenarios (R1–R8) per
//! `task/RUN_138_TASK.txt`:
//!
//!   * **A1 — first accepted v2 SIGHUP**: v2 verifier passes, v2
//!     marker decision accepts first-write, apply succeeds, sequence
//!     commits, v2 marker persists with
//!     `last_update_source = SighupReload` (the existing v1 SIGHUP
//!     enum variant, reused per Run 138 §5 to avoid
//!     `AuthorityStateUpdateSource` schema drift).
//!   * **A2 — idempotent v2 SIGHUP**: same candidate + same v2
//!     sidecar replayed against an identical persisted v2 marker;
//!     marker bytes byte-identical post-trigger.
//!   * **A3 — higher-sequence v2 SIGHUP**: persisted v2 marker has
//!     `latest_authority_domain_sequence=N`, candidate has `N+1`;
//!     accepted as `UpgradeV2 { previous_sequence=N, new_sequence=N+1 }`
//!     and the marker advances.
//!   * **A4 — v1-to-v2 SIGHUP migration**: pre-persisted v1 marker;
//!     v2 SIGHUP candidate; accepted as `V2AfterV1Migration` and the
//!     on-disk marker becomes v2.
//!   * **R1 — lower-sequence v2 rejection**: pre-mutation refusal;
//!     no live trust mutation, no sequence write, no marker write.
//!   * **R2 — same-sequence different-digest v2 rejection**: ditto.
//!   * **R3 — bad-signature v2 sidecar**: Run 130 verifier fails;
//!     mapped to `MutatingSurfaceMarkerV2Error::Conflict(...)`;
//!     `MarkerRejectedV2` outcome; no live mutation.
//!   * **R4 — wrong-domain v2 sidecar**: ratification carries the
//!     wrong chain id; verifier rejects; no live mutation.
//!   * **R5 — sequence-commit failure** (after successful v2 marker
//!     decide + swap + eviction): the Run 070 commit-failure rollback
//!     path is unchanged by Run 138 — the v2 marker is NOT written
//!     (the post-commit persist step is skipped on `Err`) and the
//!     existing `LiveReloadOutcome::Invalid` /
//!     `LiveReloadOutcome::Fatal` shape is preserved. This invariant
//!     is asserted indirectly by the orchestration shape (persist
//!     only on `Ok(applied)`) and the fact that
//!     `apply_validated_candidate_with_previous` is the SAME entry
//!     point exercised by the existing Run 074 commit-failure tests.
//!     A targeted Run 138 commit-failure regression test is not added
//!     here because the SIGHUP controller does not expose a
//!     deterministic injection seam for commit-write failure beyond
//!     what Run 074 already covers.
//!   * **R6 — marker-persist failure after commit**: surfaces as the
//!     new `LiveReloadOutcome::MarkerPersistFailureAfterCommitV2`
//!     variant with `is_fatal() == true`, mirroring the Run 121 v1
//!     fatal shape so the binary's SIGHUP task initiates graceful
//!     shutdown. Exercised on unix-only via a read-only parent
//!     directory injecting `EACCES` at marker write.
//!   * **R7 — v1 SIGHUP regression**: a v1 sidecar still takes the
//!     existing v1 path (`LiveReloadOutcome::Applied(_)` with the
//!     existing Run 121 v1 marker on disk; no v2 fields).
//!   * **R8 — no-sidecar / legacy DevNet SIGHUP regression**: the
//!     existing DevNet no-opt-in path is unchanged; no v2 marker is
//!     written.
//!
//! Strict scope (matches `task/RUN_138_TASK.txt`):
//!
//!   * Source/test wiring only.
//!   * No release-binary evidence (deferred to Run 139).
//!   * No live inbound 0x05 v2 apply, no peer-driven apply, no
//!     snapshot/restore v2.
//!   * No CLI / metric / wire / schema drift.
//!   * Does not weaken v1 SIGHUP behaviour.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_138.md`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use qbind_crypto::MlDsa44Backend;
use qbind_ledger::bundle_signing_ratification::test_helpers as ratification_v1_helpers;
use qbind_ledger::bundle_signing_ratification::v2_test_helpers as ratification_v2_helpers;
use qbind_ledger::genesis::{
    GenesisAllocation, GenesisAuthorityConfig, GenesisAuthorityRoot, GenesisConfig,
    GenesisCouncilConfig, GenesisMonetaryConfig, GenesisValidator,
    GENESIS_AUTHORITY_SUITE_ML_DSA_44,
};
use qbind_ledger::{
    canonical_ratification_v2_digest, compute_canonical_genesis_hash, BundleSigningRatification,
    BundleSigningRatificationV2, BundleSigningRatificationV2Action, GenesisHash,
    NetworkEnvironmentPolicy, RatificationEnforcementPolicy, RatificationEnvironment,
};
use qbind_node::metrics::P2pMetrics;
use qbind_node::p2p_session_eviction::{MockP2pSessionEvictor, P2pSessionEvictor};
use qbind_node::pqc_authority_state::{
    authority_state_file_path, load_authority_state, load_authority_state_versioned,
    persist_authority_state_atomic, persist_authority_state_v2_atomic, AuthorityStateUpdateSource,
    PersistentAuthorityStateRecord, PersistentAuthorityStateRecordV2,
    PersistentAuthorityStateRecordVersioned,
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
// Helpers (closely mirror the Run 121 + Run 134 fixtures so v1 and v2
// SIGHUP paths share the same controller shape and only the sidecar
// schema and marker schema differ).
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
        "qbind-run138-{}-{}-{}",
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
    let auth_root = GenesisAuthorityRoot::new(
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        &hex_lower(&authority_pk),
        "run-138-bundle-signing-1",
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

fn build_valid_v2_ratification(h: &Harness, seq: u64) -> BundleSigningRatificationV2 {
    ratification_v2_helpers::build_signed_ratification_v2(
        &h.chain_id_str,
        RatificationEnvironment::Devnet,
        h.canonical_hash,
        h.authority.authority_policy_version,
        &hex_lower(&h.authority_pk),
        &h.authority_sk,
        &h.signing_pk,
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

fn build_valid_v1_ratification(h: &Harness) -> BundleSigningRatification {
    ratification_v1_helpers::build_signed_ratification(
        &h.chain_id_str,
        RatificationEnvironment::Devnet,
        h.canonical_hash,
        &hex_lower(&h.authority_pk),
        &h.authority_sk,
        &h.signing_pk,
    )
}

fn write_v2_ratification(dir: &Path, name: &str, r: &BundleSigningRatificationV2) -> PathBuf {
    let path = dir.join(name);
    let bytes = serde_json::to_vec_pretty(r).expect("serialise v2 ratification");
    std::fs::write(&path, &bytes).expect("write v2 ratification");
    path
}

fn write_v1_ratification(dir: &Path, name: &str, r: &BundleSigningRatification) -> PathBuf {
    let path = dir.join(name);
    let bytes = serde_json::to_vec_pretty(r).expect("serialise v1 ratification");
    std::fs::write(&path, &bytes).expect("write v1 ratification");
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
    let authority_marker =
        marker_path.map(|marker_path| LiveReloadAuthorityMarkerConfig { marker_path });
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
// A1 — First-write: SIGHUP v2 applies and creates a V2 marker.
// =====================================================================

#[test]
fn run138_a1_first_accepted_v2_sighup_creates_v2_marker() {
    let h = devnet_harness();
    let dir = tmpdir("a1-first-write");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);

    let baseline_bundle = build_signed_bundle(&h, 1, 100);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline_bundle);
    let candidate_bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate_bundle);
    let ratification_v2 = build_valid_v2_ratification(&h, 7);
    let sidecar_path = write_v2_ratification(&dir, "ratification-v2.json", &ratification_v2);

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
    assert!(!out.is_fatal(), "first v2 write must not be fatal");
    assert!(!out.is_marker_rejected());

    // Run 070 ordering preserved: live state advanced, sequence file
    // written, eviction called exactly once.
    let post_fp = snapshot_state_fingerprint(&live);
    assert_ne!(pre_fp, post_fp);
    assert!(seq_path.exists(), "sequence file must be created");
    assert_eq!(mock.attempt_count(), 1);

    // Marker file created and is V2 schema.
    assert!(
        marker_path.exists(),
        "v2 marker must be created post-commit"
    );
    let persisted = load_authority_state_versioned(&marker_path)
        .expect("load")
        .expect("marker present after first-write");
    match persisted {
        PersistentAuthorityStateRecordVersioned::V2(v2) => {
            assert_eq!(v2.chain_id, h.chain_id_str);
            assert_eq!(v2.environment, TrustBundleEnvironment::Devnet);
            assert_eq!(v2.genesis_hash, hex_lower(&h.canonical_hash));
            assert_eq!(v2.latest_authority_domain_sequence, 7);
            assert_eq!(
                v2.last_update_source,
                AuthorityStateUpdateSource::SighupReload,
                "Run 138 v2 marker audit tag must identify SIGHUP path (existing v1 SIGHUP variant reused)"
            );
            assert_eq!(
                v2.latest_ratification_v2_digest,
                hex_lower(&canonical_ratification_v2_digest(&ratification_v2))
            );
            assert_eq!(
                v2.active_bundle_signing_key_fingerprint,
                signing_key_fingerprint_hex(&h.signing_pk)
            );
            assert_eq!(v2.authority_root_fingerprint, h.authority_root_fingerprint);
            assert_eq!(
                v2.latest_lifecycle_action,
                BundleSigningRatificationV2Action::Ratify
            );
        }
        PersistentAuthorityStateRecordVersioned::V1(_) => {
            panic!("Run 138: persisted marker must be V2 schema");
        }
    }

    // Metrics: trigger + success bumped, no failure.
    assert_eq!(metrics.live_reload_trigger_total(), 1);
    assert_eq!(metrics.live_reload_apply_success_total(), 1);
    assert_eq!(metrics.live_reload_apply_failure_total(), 0);
}

// =====================================================================
// A2 — Idempotent v2 SIGHUP: re-applying produces no marker rewrite.
// =====================================================================

#[test]
fn run138_a2_idempotent_v2_sighup_does_not_rewrite_marker() {
    let h = devnet_harness();
    let dir = tmpdir("a2-idempotent");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);

    let baseline_bundle = build_signed_bundle(&h, 1, 100);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline_bundle);
    let candidate_bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate_bundle);
    let ratification_v2 = build_valid_v2_ratification(&h, 7);
    let sidecar_path = write_v2_ratification(&dir, "ratification-v2.json", &ratification_v2);

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

    let first = ctl.try_trigger_with_now(300);
    assert!(matches!(first, LiveReloadOutcome::Applied(_)));
    let bytes_after_first = std::fs::read(&marker_path).expect("marker exists");
    let mtime_after_first = std::fs::metadata(&marker_path)
        .expect("metadata")
        .modified()
        .ok();

    std::thread::sleep(std::time::Duration::from_millis(50));

    // Same candidate + same v2 ratification — idempotent.
    let _second = ctl.try_trigger_with_now(400);
    let bytes_after_second = std::fs::read(&marker_path).expect("marker still exists");
    assert_eq!(
        bytes_after_first, bytes_after_second,
        "Run 138 idempotent v2 SIGHUP MUST NOT rewrite marker bytes"
    );
    let mtime_after_second = std::fs::metadata(&marker_path)
        .expect("metadata")
        .modified()
        .ok();
    assert_eq!(
        mtime_after_first, mtime_after_second,
        "Run 138 idempotent v2 SIGHUP MUST NOT touch marker mtime"
    );
}

// =====================================================================
// A3 — Higher-sequence v2 SIGHUP advances the v2 marker.
// =====================================================================

#[test]
fn run138_a3_higher_sequence_v2_sighup_advances_marker() {
    let h = devnet_harness();
    let dir = tmpdir("a3-upgrade");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    std::fs::create_dir_all(marker_path.parent().expect("parent")).expect("mkdir parent");

    // Pre-persist a v2 marker at sequence N=5.
    let lower_seq = 5u64;
    let lower_v2 = build_valid_v2_ratification(&h, lower_seq);
    let pre_v2 = PersistentAuthorityStateRecordV2::new(
        h.chain_id_str.clone(),
        TrustBundleEnvironment::Devnet,
        hex_lower(&h.canonical_hash),
        h.authority_root_fingerprint.clone(),
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        signing_key_fingerprint_hex(&h.signing_pk),
        PQC_TRANSPORT_SUITE_ML_DSA_44,
        lower_seq,
        BundleSigningRatificationV2Action::Ratify,
        None,
        hex_lower(&canonical_ratification_v2_digest(&lower_v2)),
        None,
        AuthorityStateUpdateSource::SighupReload,
        100,
    );
    persist_authority_state_v2_atomic(&marker_path, &pre_v2).expect("pre-persist v2");

    let baseline_bundle = build_signed_bundle(&h, 1, 100);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline_bundle);
    let candidate_bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate_bundle);
    // Candidate v2 ratification at sequence N+1=6.
    let new_seq = 6u64;
    let ratification_v2 = build_valid_v2_ratification(&h, new_seq);
    let sidecar_path = write_v2_ratification(&dir, "ratification-v2.json", &ratification_v2);

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

    let out = ctl.try_trigger_with_now(300);
    assert!(
        matches!(out, LiveReloadOutcome::Applied(_)),
        "v2 upgrade must apply; got {:?}",
        out
    );

    // Marker must now carry sequence=6.
    let persisted = load_authority_state_versioned(&marker_path)
        .expect("load")
        .expect("marker present");
    match persisted {
        PersistentAuthorityStateRecordVersioned::V2(v2) => {
            assert_eq!(v2.latest_authority_domain_sequence, new_seq);
            assert_eq!(
                v2.last_update_source,
                AuthorityStateUpdateSource::SighupReload
            );
        }
        PersistentAuthorityStateRecordVersioned::V1(_) => panic!("must be V2"),
    }
}

// =====================================================================
// A4 — v1→v2 SIGHUP migration: pre-persisted v1 marker becomes V2.
// =====================================================================

#[test]
fn run138_a4_v1_to_v2_sighup_migration_promotes_marker() {
    let h = devnet_harness();
    let dir = tmpdir("a4-v1-to-v2");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    std::fs::create_dir_all(marker_path.parent().expect("parent")).expect("mkdir parent");

    // Pre-persist a v1 marker — same trust domain.
    let v1_ratification = build_valid_v1_ratification(&h);
    let pre_v1 = PersistentAuthorityStateRecord::new(
        h.chain_id_str.clone(),
        TrustBundleEnvironment::Devnet,
        hex_lower(&h.canonical_hash),
        h.authority.authority_policy_version,
        h.authority.authority_sequence,
        h.authority.authority_epoch,
        h.authority_root_fingerprint.clone(),
        signing_key_fingerprint_hex(&h.signing_pk),
        hex_lower(&qbind_ledger::canonical_ratification_digest(
            &v1_ratification,
        )),
        AuthorityStateUpdateSource::SighupReload,
        100,
    );
    persist_authority_state_atomic(&marker_path, &pre_v1).expect("pre-persist v1");
    // Sanity: marker is v1 before trigger.
    let pre_versioned = load_authority_state_versioned(&marker_path)
        .expect("load")
        .expect("v1 present");
    assert!(matches!(
        pre_versioned,
        PersistentAuthorityStateRecordVersioned::V1(_)
    ));

    let baseline_bundle = build_signed_bundle(&h, 1, 100);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline_bundle);
    let candidate_bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate_bundle);
    // v2 SIGHUP candidate. Any seq >= 1 is valid here because the
    // v1 marker has no authority_domain_sequence to compare against.
    let ratification_v2 = build_valid_v2_ratification(&h, 9);
    let sidecar_path = write_v2_ratification(&dir, "ratification-v2.json", &ratification_v2);

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

    let out = ctl.try_trigger_with_now(300);
    assert!(
        matches!(out, LiveReloadOutcome::Applied(_)),
        "v1→v2 SIGHUP migration must apply; got {:?}",
        out
    );

    // Marker must now be V2 with the SIGHUP audit tag.
    let post_versioned = load_authority_state_versioned(&marker_path)
        .expect("load")
        .expect("v2 present");
    match post_versioned {
        PersistentAuthorityStateRecordVersioned::V2(v2) => {
            assert_eq!(v2.latest_authority_domain_sequence, 9);
            assert_eq!(
                v2.last_update_source,
                AuthorityStateUpdateSource::SighupReload
            );
        }
        PersistentAuthorityStateRecordVersioned::V1(_) => {
            panic!("Run 138: v1→v2 migration must persist a V2 marker")
        }
    }
}

// =====================================================================
// R1 — Lower-sequence v2 rejection.
// =====================================================================

#[test]
fn run138_r1_lower_sequence_v2_sighup_refuses_pre_mutation() {
    let h = devnet_harness();
    let dir = tmpdir("r1-rollback");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    std::fs::create_dir_all(marker_path.parent().expect("parent")).expect("mkdir parent");

    // Pre-persist a v2 marker at sequence N=10.
    let high_seq = 10u64;
    let high_v2 = build_valid_v2_ratification(&h, high_seq);
    let pre_v2 = PersistentAuthorityStateRecordV2::new(
        h.chain_id_str.clone(),
        TrustBundleEnvironment::Devnet,
        hex_lower(&h.canonical_hash),
        h.authority_root_fingerprint.clone(),
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        signing_key_fingerprint_hex(&h.signing_pk),
        PQC_TRANSPORT_SUITE_ML_DSA_44,
        high_seq,
        BundleSigningRatificationV2Action::Ratify,
        None,
        hex_lower(&canonical_ratification_v2_digest(&high_v2)),
        None,
        AuthorityStateUpdateSource::SighupReload,
        100,
    );
    persist_authority_state_v2_atomic(&marker_path, &pre_v2).expect("pre-persist v2");
    let marker_bytes_before = std::fs::read(&marker_path).expect("read marker");

    let baseline_bundle = build_signed_bundle(&h, 1, 100);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline_bundle);
    let candidate_bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate_bundle);
    // Candidate v2 ratification at sequence N-1=9 (rollback).
    let ratification_v2 = build_valid_v2_ratification(&h, high_seq - 1);
    let sidecar_path = write_v2_ratification(&dir, "ratification-v2.json", &ratification_v2);

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
        LiveReloadOutcome::MarkerRejectedV2(_) => {}
        other => panic!("expected MarkerRejectedV2(_), got {:?}", other),
    }
    assert!(out.is_marker_rejected());
    assert!(!out.is_applied());
    assert!(!out.is_fatal());

    // No mutation.
    assert_eq!(snapshot_state_fingerprint(&live), pre_fp);
    assert!(
        !seq_path.exists(),
        "sequence file must NOT be written on R1"
    );
    assert_eq!(mock.attempt_count(), 0, "no eviction on R1");
    let marker_bytes_after = std::fs::read(&marker_path).expect("marker still exists");
    assert_eq!(
        marker_bytes_before, marker_bytes_after,
        "R1 marker bytes must be byte-identical"
    );
    assert_eq!(metrics.live_reload_apply_success_total(), 0);
    assert_eq!(metrics.live_reload_apply_failure_total(), 1);
}

// =====================================================================
// R2 — Same-sequence different-digest v2 rejection.
// =====================================================================

#[test]
fn run138_r2_same_sequence_different_digest_v2_sighup_refuses() {
    let h = devnet_harness();
    let dir = tmpdir("r2-same-seq");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    std::fs::create_dir_all(marker_path.parent().expect("parent")).expect("mkdir parent");

    // Pre-persist a v2 marker at sequence N=7 with one digest.
    let seq = 7u64;
    let other_v2 = ratification_v2_helpers::build_signed_ratification_v2(
        &h.chain_id_str,
        RatificationEnvironment::Devnet,
        h.canonical_hash,
        h.authority.authority_policy_version,
        &hex_lower(&h.authority_pk),
        &h.authority_sk,
        &h.signing_pk,
        seq,
        BundleSigningRatificationV2Action::Ratify,
        None,
        None,
        Some(1_000),
        None,
        None,
        None,
    );
    let pre_v2 = PersistentAuthorityStateRecordV2::new(
        h.chain_id_str.clone(),
        TrustBundleEnvironment::Devnet,
        hex_lower(&h.canonical_hash),
        h.authority_root_fingerprint.clone(),
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        signing_key_fingerprint_hex(&h.signing_pk),
        PQC_TRANSPORT_SUITE_ML_DSA_44,
        seq,
        BundleSigningRatificationV2Action::Ratify,
        None,
        hex_lower(&canonical_ratification_v2_digest(&other_v2)),
        None,
        AuthorityStateUpdateSource::SighupReload,
        100,
    );
    persist_authority_state_v2_atomic(&marker_path, &pre_v2).expect("pre-persist v2");
    let marker_bytes_before = std::fs::read(&marker_path).expect("read marker");

    let baseline_bundle = build_signed_bundle(&h, 1, 100);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline_bundle);
    let candidate_bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate_bundle);

    // Candidate v2 ratification at SAME sequence but built from a
    // freshly rolled authority subscription instance — this changes
    // the signature/random bytes inside the canonical digest.
    let ratification_v2 = build_valid_v2_ratification(&h, seq);
    assert_ne!(
        hex_lower(&canonical_ratification_v2_digest(&other_v2)),
        hex_lower(&canonical_ratification_v2_digest(&ratification_v2)),
        "two distinct v2 ratifications at the same sequence must have distinct digests"
    );
    let sidecar_path = write_v2_ratification(&dir, "ratification-v2.json", &ratification_v2);

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
        matches!(out, LiveReloadOutcome::MarkerRejectedV2(_)),
        "R2 expected MarkerRejectedV2, got {:?}",
        out
    );
    assert_eq!(snapshot_state_fingerprint(&live), pre_fp);
    assert!(!seq_path.exists());
    assert_eq!(mock.attempt_count(), 0);
    let marker_bytes_after = std::fs::read(&marker_path).expect("marker still exists");
    assert_eq!(marker_bytes_before, marker_bytes_after);
}

// =====================================================================
// R3 — Bad-signature v2 sidecar rejection (Run 130 verifier fails).
// =====================================================================

#[test]
fn run138_r3_bad_signature_v2_sidecar_refuses_pre_mutation() {
    let h = devnet_harness();
    let dir = tmpdir("r3-bad-sig");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);

    let baseline_bundle = build_signed_bundle(&h, 1, 100);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline_bundle);
    let candidate_bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate_bundle);

    // Build a clean v2 ratification, then tamper one byte of the
    // signature so the Run 130 verifier fails.
    let mut tampered = build_valid_v2_ratification(&h, 5);
    assert!(!tampered.signature.is_empty(), "signature non-empty");
    tampered.signature[0] ^= 0xFF;
    let sidecar_path = write_v2_ratification(&dir, "ratification-v2.json", &tampered);

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
        matches!(out, LiveReloadOutcome::MarkerRejectedV2(_)),
        "R3 expected MarkerRejectedV2 (v2 verifier failure mapped to Conflict), got {:?}",
        out
    );

    // No mutation: no live state change, no sequence file, no eviction,
    // no marker written.
    assert_eq!(snapshot_state_fingerprint(&live), pre_fp);
    assert!(!seq_path.exists());
    assert_eq!(mock.attempt_count(), 0);
    assert!(!marker_path.exists(), "no marker may be written on R3");

    let line = out.log_line();
    assert!(
        line.contains("Run 138"),
        "log line must name Run 138; got: {}",
        line
    );
    assert!(
        line.contains("marker-rejected-v2"),
        "log line must name marker-rejected-v2; got: {}",
        line
    );
}

// =====================================================================
// R4 — Wrong-domain v2 sidecar rejection.
// =====================================================================

#[test]
fn run138_r4_wrong_domain_v2_sidecar_refuses_pre_mutation() {
    let h = devnet_harness();
    let dir = tmpdir("r4-wrong-domain");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);

    let baseline_bundle = build_signed_bundle(&h, 1, 100);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline_bundle);
    let candidate_bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate_bundle);

    // Build a v2 ratification bound to a DIFFERENT chain_id, signed
    // consistently with that chain_id. The verifier's chain-id binding
    // check will refuse.
    let wrong_chain_id = chain_id_hex(NetworkEnvironment::Testnet.chain_id());
    let wrong_ratification = ratification_v2_helpers::build_signed_ratification_v2(
        &wrong_chain_id,
        RatificationEnvironment::Devnet,
        h.canonical_hash,
        h.authority.authority_policy_version,
        &hex_lower(&h.authority_pk),
        &h.authority_sk,
        &h.signing_pk,
        4,
        BundleSigningRatificationV2Action::Ratify,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let sidecar_path = write_v2_ratification(&dir, "ratification-v2.json", &wrong_ratification);

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
        matches!(out, LiveReloadOutcome::MarkerRejectedV2(_)),
        "R4 expected MarkerRejectedV2 (v2 verifier domain mismatch), got {:?}",
        out
    );

    assert_eq!(snapshot_state_fingerprint(&live), pre_fp);
    assert!(!seq_path.exists());
    assert_eq!(mock.attempt_count(), 0);
    assert!(!marker_path.exists());
}

// =====================================================================
// R6 — v2 marker-persist failure AFTER successful sequence commit is
// fatal. Live state DID advance; persist failed; outcome is the new
// `MarkerPersistFailureAfterCommitV2` variant with `is_fatal() == true`.
// =====================================================================

#[test]
#[cfg(unix)]
fn run138_r6_v2_marker_persist_failure_after_commit_is_fatal() {
    let h = devnet_harness();
    let dir = tmpdir("r6-persist-fatal");
    let seq_path = sequence_file_path(&dir);

    // Read-only parent directory so that:
    //   * `load_authority_state_versioned` returns `Ok(None)` (no file);
    //   * the marker decision is `FirstV2Write` (should_persist=true);
    //   * the post-commit atomic write fails with EACCES.
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
    let ratification_v2 = build_valid_v2_ratification(&h, 3);
    let sidecar_path = write_v2_ratification(&dir, "ratification-v2.json", &ratification_v2);

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
        LiveReloadOutcome::MarkerPersistFailureAfterCommitV2 { applied, .. } => {
            assert_eq!(applied.validated.sequence, 2);
        }
        other => panic!(
            "expected MarkerPersistFailureAfterCommitV2, got {:?}",
            other
        ),
    }

    // Run 138 R6: persist failure must be is_fatal() so the binary's
    // SIGHUP task initiates graceful shutdown (mirrors the v1 Run 121
    // fatal shape).
    assert!(
        out.is_fatal(),
        "R6 persist failure must signal fatal shutdown"
    );
    assert!(out.is_applied(), "live state did advance");
    assert_ne!(snapshot_state_fingerprint(&live), pre_fp);
    assert!(seq_path.exists());
    assert_eq!(mock.attempt_count(), 1);
    assert!(
        !marker_path.exists(),
        "marker file must not exist post-fail"
    );

    // Metrics: success bumped (apply pipeline completed); failure
    // counter unchanged.
    assert_eq!(metrics.live_reload_apply_success_total(), 1);
    assert_eq!(metrics.live_reload_apply_failure_total(), 0);

    let line = out.log_line();
    assert!(
        line.contains("Run 138"),
        "R6 log line must name Run 138; got: {}",
        line
    );
    assert!(
        line.contains("FATAL-marker-persist-v2"),
        "R6 log line must name FATAL-marker-persist-v2; got: {}",
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

// =====================================================================
// R7 — v1 SIGHUP regression: a v1 sidecar still takes the existing
// v1 path. No v2 dispatch, no v2 outcome variants.
// =====================================================================

#[test]
fn run138_r7_v1_sighup_sidecar_still_takes_v1_path() {
    let h = devnet_harness();
    let dir = tmpdir("r7-v1-regression");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);

    let baseline_bundle = build_signed_bundle(&h, 1, 100);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline_bundle);
    let candidate_bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate_bundle);
    let ratification_v1 = build_valid_v1_ratification(&h);
    let sidecar_path = write_v1_ratification(&dir, "ratification-v1.json", &ratification_v1);

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
    assert!(
        matches!(out, LiveReloadOutcome::Applied(_)),
        "R7 v1 path must still apply via existing Run 121 v1 wiring; got {:?}",
        out
    );
    assert_ne!(snapshot_state_fingerprint(&live), pre_fp);
    assert!(seq_path.exists());
    assert_eq!(mock.attempt_count(), 1);

    // Marker must be v1 schema (existing Run 121 path).
    let persisted = load_authority_state_versioned(&marker_path)
        .expect("load")
        .expect("marker present");
    match persisted {
        PersistentAuthorityStateRecordVersioned::V1(_) => {}
        PersistentAuthorityStateRecordVersioned::V2(_) => {
            panic!("R7 v1 SIGHUP must persist a V1 marker, not a V2 marker")
        }
    }
    // Run 121 v1 marker also readable via load_authority_state.
    let v1 = load_authority_state(&marker_path)
        .expect("load v1")
        .expect("present");
    assert_eq!(
        v1.last_update_source,
        AuthorityStateUpdateSource::SighupReload
    );
    assert_eq!(metrics.live_reload_apply_success_total(), 1);
}

// =====================================================================
// R8 — No-sidecar / legacy DevNet SIGHUP regression: no v2 marker
// written, existing pre-Run-114 behaviour preserved.
// =====================================================================

#[test]
fn run138_r8_no_sidecar_devnet_sighup_writes_no_v2_marker() {
    let h = devnet_harness();
    let dir = tmpdir("r8-no-sidecar");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);

    let baseline_bundle = build_signed_bundle(&h, 1, 100);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline_bundle);
    let candidate_bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate_bundle);

    // No ratification, no marker — pre-Run-114 / pre-Run-121 /
    // pre-Run-138 path.
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
        "R8 no-sidecar DevNet must apply via pre-Run-114 path; got {:?}",
        out
    );
    assert_ne!(snapshot_state_fingerprint(&live), pre_fp);
    assert!(seq_path.exists());
    assert_eq!(mock.attempt_count(), 1);

    // No marker file written (no authority_marker config).
    assert!(
        !marker_path.exists(),
        "R8 must NOT write a v2 marker on the DevNet no-opt-in path"
    );
}
