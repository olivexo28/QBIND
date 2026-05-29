//! Run 152 — integration tests for the **binary-reachable, peer-driven
//! drain invocation plumbing** that lets the hidden
//! `--p2p-trust-bundle-peer-candidate-drain-once` flag construct a real
//! drain invocation from the live staged peer-candidate queue.
//!
//! Unlike the Run 150 tests (which used purely test-local doubles for the
//! `PeerDrivenDrainInvocationBuilder` and `V2MarkerCoordinator`), these
//! tests exercise the **production** plumbing types added in Run 152:
//!
//!   * [`qbind_node::pqc_peer_candidate_drain::ProductionDrainInvocationBuilder`]
//!     — the production builder that re-derives `ReloadCheckInputs` from
//!     owned candidate material and fail-closes on stale / wrong-domain /
//!     missing-v2 staged metadata before ever calling Run 148.
//!   * [`qbind_node::pqc_peer_candidate_apply::ProductionV2MarkerCoordinator`]
//!     — the production coordinator that runs the real Run 134
//!     `decide_marker_acceptance_v2` pre-apply decision and the real
//!     `persist_accepted_v2_marker_after_commit_boundary` post-commit
//!     write.
//!   * [`qbind_node::pqc_peer_candidate_drain::try_drain_once_shared`]
//!     — the binary-reachable orchestration helper that locks the SAME
//!     `Arc<parking_lot::Mutex<PeerCandidateStagingQueue>>` the live
//!     inbound `0x05` validation-only path installs on the wire
//!     dispatcher, and delegates to the Run 150 drain.
//!
//! Acceptance matrix (`task/RUN_152_TASK.txt`):
//!
//!   * **A1** the shared queue staged by the live-inbound path is the
//!     exact queue the drain hook consumes; no mutation before an
//!     explicit, enabled drain.
//!   * **A2** DevNet: production builder constructs a real invocation
//!     (no write during build) and the drain applies end-to-end,
//!     persisting a real v2 marker after commit.
//!   * **A3** TestNet: same as A2 under an explicit TestNet policy /
//!     TestNet-signed candidate (no MainNet inference).
//!   * **A4** the drain routes through Run 150 → Run 148 → Run 070 in
//!     strict order.
//!   * **A5** the v2 marker persist happens strictly AFTER the Run 070
//!     `commit_sequence` boundary (unified ordered timeline).
//!   * **A6** a second drain after a successful apply cannot double-apply.
//!   * **A7** the concurrency guard prevents a re-entrant drain.
//!   * **R1** disabled policy → no mutation.
//!   * **R2** MainNet → refused before the queue is consulted.
//!   * **R3** empty shared queue → `NoCandidate`.
//!   * **R4** expired staged candidate → not selected; no mutation.
//!   * **R5** lower-sequence candidate vs a persisted higher-sequence v2
//!     marker → real `CandidateMarkerConflict`; no Run 070; marker
//!     bytes preserved.
//!   * **R6** same-sequence different-digest equivocation vs a persisted
//!     v2 marker → real `CandidateMarkerConflict`; no Run 070.
//!   * **R7** bad-signature on-disk bundle → Run 070 validation refuses
//!     before swap.
//!   * **R8** wrong-domain staged candidate → not selected; no mutation.
//!   * **R9** missing v2 marker digest (ambiguous v1+v2) → production
//!     builder fail-closes before apply.
//!   * **R10** corrupted local marker → real `CandidateMarkerConflict`;
//!     corrupt bytes preserved (never repaired).
//!   * **R11** Run 070 validation failure before swap → no mutation.
//!   * **R12** Run 070 eviction failure → rollback; no commit; no marker.
//!   * **R13** Run 070 commit failure → rollback; no marker persisted.
//!   * **R14** marker persist failure AFTER commit → fatal /
//!     operator-actionable.
//!   * **R15** v1/legacy path unchanged: with the v2 gate disabled the
//!     production builder still constructs an invocation for a
//!     no-digest candidate (no write during build).
//!   * **R16** propagation-only behaviour unchanged: a non-applying
//!     drain leaves the staging queue identical.
//!
//! # Strict scope (Run 152)
//!
//! - Source / test wiring only. NO release-binary end-to-end harness;
//!   the `main.rs` hook is arming-only and does NOT autonomously invoke
//!   a drain. Release-binary end-to-end evidence is deferred to Run 153.
//! - DevNet / TestNet only — MainNet refused unconditionally.
//! - Reuses, and does not weaken, the Run 070 / 142 / 145 / 146 / 148 /
//!   149 / 150 / 151 contracts.

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use parking_lot::Mutex as PlMutex;

use qbind_crypto::MlDsa44Backend;
use qbind_ledger::{
    bundle_signing_ratification::v2_test_helpers as ratification_v2_helpers,
    compute_canonical_genesis_hash, BundleSigningRatificationV2,
    BundleSigningRatificationV2Action, GenesisAllocation, GenesisAuthorityConfig,
    GenesisAuthorityRoot, GenesisConfig, GenesisCouncilConfig, GenesisHash,
    GenesisMonetaryConfig, GenesisValidator, NetworkEnvironmentPolicy, RatificationEnvironment,
    GENESIS_AUTHORITY_SUITE_ML_DSA_44,
};
use qbind_node::pqc_authority_state::{
    authority_state_file_path, load_authority_state_versioned, AuthorityStateUpdateSource,
    PersistentAuthorityStateRecordVersioned,
};
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_peer_candidate_apply::{
    PeerDrivenApplyOutcome, PeerDrivenApplyPolicy, PeerDrivenApplyRuntimeDomain,
    ProductionV2MarkerCoordinator, V2MarkerCoordinator,
};
use qbind_node::pqc_peer_candidate_drain::{
    try_drain_once_shared, PeerDrivenApplyDrain, PeerDrivenDrainOutcome, PeerDrivenDrainPolicy,
    ProductionDrainInvocationBuilder,
};
use qbind_node::pqc_peer_candidate_staging::{
    PeerCandidateStagingQueue, PeerDrivenStagingPolicy, StagingOutcome,
};
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
use qbind_node::pqc_trust_activation::ActivationContext;
use qbind_node::pqc_trust_bundle::{
    derive_signing_key_id, sign_bundle_devnet_helper, BundleSigningKey, BundleSigningKeySet,
    LoadedTrustBundle, RootStatus, TrustBundle, TrustBundleEnvironment, TrustBundleRevocation,
    TrustBundleRoot,
};
use qbind_node::pqc_trust_peer_candidate::ValidatedPeerCandidate;
use qbind_node::pqc_trust_reload::{
    validate_candidate_bundle, LiveTrustApplyContext, ReloadCheckInputs, ValidatedCandidate,
};
use qbind_node::pqc_trust_sequence::{
    atomic_write_record, chain_id_hex, sequence_file_path, PersistentTrustBundleSequenceRecord,
};
use qbind_types::NetworkEnvironment;

type SharedQueue = Arc<PlMutex<PeerCandidateStagingQueue>>;

// =====================================================================
// Generic helpers.
// =====================================================================

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
        "qbind-run152-{}-{}-{}",
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

// =====================================================================
// Unified harness: bundle-signing material (Run 069/070) + v2
// ratification / genesis material (Run 130/134), parametrised by
// environment so the TestNet acceptance test (A3) is a genuine positive.
// =====================================================================

struct Harness {
    env: NetworkEnvironment,
    trust_env: TrustBundleEnvironment,
    signing_keys: BundleSigningKeySet,
    signing_pk: Vec<u8>,
    signing_key_id: [u8; 32],
    signing_sk: Vec<u8>,
    /// A second, independent signing key — used to forge a
    /// same-sequence different-digest equivocation (R6).
    alt_signing_pk: Vec<u8>,
    root_id_hex: String,
    root_pk_hex: String,
    authority_pk: Vec<u8>,
    authority_sk: Vec<u8>,
    genesis_cfg: GenesisConfig,
    canonical_hash: GenesisHash,
    chain_id_str: String,
    env_policy: NetworkEnvironmentPolicy,
    ratification_env: RatificationEnvironment,
}

fn harness(env: NetworkEnvironment) -> Harness {
    let (signing_pk, signing_sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen signing key");
    let signing_key_id = derive_signing_key_id(&signing_pk);
    let signing_keys = BundleSigningKeySet::from_keys_unchecked(vec![BundleSigningKey {
        key_id_bytes: signing_key_id,
        suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
        pk_bytes: signing_pk.clone(),
    }]);
    let (alt_signing_pk, _alt_sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen alt signing key");
    let root = mint_devnet_root().expect("mint root");
    let (authority_pk, authority_sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen authority key");
    let chain_id = env.chain_id();
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
    let (env_policy, ratification_env, trust_env) = match env {
        NetworkEnvironment::Devnet => (
            NetworkEnvironmentPolicy::Devnet,
            RatificationEnvironment::Devnet,
            TrustBundleEnvironment::Devnet,
        ),
        NetworkEnvironment::Testnet => (
            NetworkEnvironmentPolicy::Testnet,
            RatificationEnvironment::Testnet,
            TrustBundleEnvironment::Testnet,
        ),
        other => panic!("harness only supports DevNet/TestNet, not {:?}", other),
    };
    let canonical_hash = compute_canonical_genesis_hash(&genesis_cfg, env_policy);

    Harness {
        env,
        trust_env,
        signing_keys,
        signing_pk,
        signing_key_id,
        signing_sk,
        alt_signing_pk,
        root_id_hex: hex_lower(&root.root_key_id),
        root_pk_hex: hex_lower(&root.root_pk),
        authority_pk,
        authority_sk,
        genesis_cfg,
        canonical_hash,
        chain_id_str,
        env_policy,
        ratification_env,
    }
}

fn devnet_harness() -> Harness {
    harness(NetworkEnvironment::Devnet)
}

fn build_signed_bundle(h: &Harness, sequence: u64, generated_at: u64) -> TrustBundle {
    let mut bundle = TrustBundle {
        bundle_version: TrustBundle::SUPPORTED_SCHEMA_VERSION,
        environment: h.trust_env,
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

fn write_bundle_to_disk(dir: &Path, name: &str, bundle: &TrustBundle) -> PathBuf {
    let path = dir.join(name);
    let bytes = serde_json::to_vec(bundle).expect("serialise bundle");
    std::fs::write(&path, &bytes).expect("write bundle");
    path
}

fn runtime_genesis_hash_hex(h: &Harness) -> String {
    hex_lower(&h.canonical_hash)
}

fn build_ratification_for(
    h: &Harness,
    seq: u64,
    ratified_signing_pk: &[u8],
) -> BundleSigningRatificationV2 {
    let authority = h.genesis_cfg.authority.as_ref().unwrap();
    let policy_version = authority.authority_policy_version;
    ratification_v2_helpers::build_signed_ratification_v2(
        &h.chain_id_str,
        h.ratification_env,
        h.canonical_hash,
        policy_version,
        &hex_lower(&h.authority_pk),
        &h.authority_sk,
        ratified_signing_pk,
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

fn build_ratification(h: &Harness, seq: u64) -> BundleSigningRatificationV2 {
    build_ratification_for(h, seq, &h.signing_pk)
}

fn ratified_v2(
    h: &Harness,
    ratification: &BundleSigningRatificationV2,
) -> qbind_ledger::RatifiedBundleSigningKeyV2 {
    qbind_ledger::verify_bundle_signing_key_ratification_v2(
        qbind_ledger::RatificationV2VerifierInputs {
            ratification,
            authority: h.genesis_cfg.authority.as_ref().unwrap(),
            expected_chain_id: &h.chain_id_str,
            expected_environment: h.env_policy,
            expected_genesis_hash: &h.canonical_hash,
        },
    )
    .expect("v2 verifier accepts clean ratification")
}

fn reload_inputs<'a>(
    h: &'a Harness,
    candidate_path: &'a Path,
    seq_path: Option<&'a Path>,
) -> ReloadCheckInputs<'a> {
    ReloadCheckInputs {
        candidate_path,
        environment: h.env,
        chain_id: h.env.chain_id(),
        validation_time_secs: 100,
        signing_keys: &h.signing_keys,
        activation_ctx: ActivationContext::height_only(0),
        sequence_persistence_path: seq_path,
        local_leaf_cert_bytes: None,
    }
}

fn runtime_domain(h: &Harness) -> PeerDrivenApplyRuntimeDomain {
    PeerDrivenApplyRuntimeDomain::new(h.env, chain_id_hex(h.env.chain_id()))
}

fn mainnet_runtime_domain() -> PeerDrivenApplyRuntimeDomain {
    PeerDrivenApplyRuntimeDomain::new(
        NetworkEnvironment::Mainnet,
        chain_id_hex(NetworkEnvironment::Mainnet.chain_id()),
    )
}

// =====================================================================
// Deterministic apply-context + marker doubles. Both push onto a
// shared timeline so the ordered apply / persist sequence can be
// asserted in a single vector (A5).
// =====================================================================

#[derive(Debug, Clone)]
enum ActionPlan {
    Ok,
    Err(String),
}

struct FakeCtx {
    timeline: Arc<Mutex<Vec<String>>>,
    active: Arc<Mutex<String>>,
    swap_action: ActionPlan,
    evict_action: ActionPlan,
    commit_action: ActionPlan,
    rollback_action: ActionPlan,
    eviction_count: usize,
}

impl FakeCtx {
    fn new(initial_fp: &str) -> Self {
        Self::with_timeline(initial_fp, Arc::new(Mutex::new(Vec::new())))
    }
    fn with_timeline(initial_fp: &str, timeline: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            timeline,
            active: Arc::new(Mutex::new(initial_fp.to_string())),
            swap_action: ActionPlan::Ok,
            evict_action: ActionPlan::Ok,
            commit_action: ActionPlan::Ok,
            rollback_action: ActionPlan::Ok,
            eviction_count: 2,
        }
    }
    fn timeline(&self) -> Arc<Mutex<Vec<String>>> {
        self.timeline.clone()
    }
    fn active(&self) -> Arc<Mutex<String>> {
        self.active.clone()
    }
    fn push(&self, ev: &str) {
        self.timeline.lock().unwrap().push(ev.to_string());
    }
}

impl LiveTrustApplyContext for FakeCtx {
    fn snapshot_active(&mut self) -> Result<Box<dyn std::any::Any + Send + Sync>, String> {
        self.push("snapshot_active");
        let prev: String = self.active.lock().unwrap().clone();
        Ok(Box::new(prev))
    }
    fn swap_trust_state(&mut self, candidate: &LoadedTrustBundle) -> Result<(), String> {
        self.push("swap_trust_state");
        match &self.swap_action {
            ActionPlan::Err(m) => Err(m.clone()),
            ActionPlan::Ok => {
                *self.active.lock().unwrap() = candidate.fingerprint_hex()[..8].to_string();
                Ok(())
            }
        }
    }
    fn evict_sessions(&mut self) -> Result<usize, String> {
        self.push("evict_sessions");
        match &self.evict_action {
            ActionPlan::Err(m) => Err(m.clone()),
            ActionPlan::Ok => Ok(self.eviction_count),
        }
    }
    fn commit_sequence(&mut self, _candidate: &LoadedTrustBundle) -> Result<(), String> {
        self.push("commit_sequence");
        match &self.commit_action {
            ActionPlan::Err(m) => Err(m.clone()),
            ActionPlan::Ok => Ok(()),
        }
    }
    fn rollback_trust_state(
        &mut self,
        snapshot: Box<dyn std::any::Any + Send + Sync>,
    ) -> Result<(), String> {
        self.push("rollback_trust_state");
        match &self.rollback_action {
            ActionPlan::Err(m) => Err(m.clone()),
            ActionPlan::Ok => {
                if let Ok(prev) = snapshot.downcast::<String>() {
                    *self.active.lock().unwrap() = *prev;
                }
                Ok(())
            }
        }
    }
}

/// Minimal marker coordinator double used only where a deterministic
/// post-commit failure (R14) or an ordered-timeline capture (A5) is
/// required. Production marker semantics are covered by
/// [`ProductionV2MarkerCoordinator`] in the positive / conflict tests.
struct MockMarker {
    timeline: Arc<Mutex<Vec<String>>>,
    pre: Result<(), String>,
    post: Result<(), String>,
}

impl MockMarker {
    fn with_timeline(timeline: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            timeline,
            pre: Ok(()),
            post: Ok(()),
        }
    }
    fn with_post_commit_err(mut self, msg: &str) -> Self {
        self.post = Err(msg.to_string());
        self
    }
}

impl V2MarkerCoordinator for MockMarker {
    fn decide_pre_apply(&mut self) -> Result<(), String> {
        self.timeline.lock().unwrap().push("decide_pre_apply".into());
        self.pre.clone()
    }
    fn persist_after_commit(&mut self) -> Result<(), String> {
        self.timeline
            .lock()
            .unwrap()
            .push("persist_after_commit".into());
        self.post.clone()
    }
}

// =====================================================================
// Construction helpers for the production plumbing.
// =====================================================================

#[allow(clippy::too_many_arguments)]
fn prod_builder(
    h: &Harness,
    candidate_path: &Path,
    seq_path: Option<&Path>,
    ctx: FakeCtx,
    previous_fingerprint_prefix: &str,
    previous_sequence: Option<u64>,
    now_unix_secs: u64,
) -> ProductionDrainInvocationBuilder<FakeCtx> {
    ProductionDrainInvocationBuilder::new(
        candidate_path.to_path_buf(),
        h.signing_keys.clone(),
        seq_path.map(|p| p.to_path_buf()),
        h.env,
        h.env.chain_id(),
        100,
        ActivationContext::height_only(0),
        None,
        ctx,
        previous_fingerprint_prefix.to_string(),
        previous_sequence,
        300,
        now_unix_secs,
    )
}

fn prod_marker(
    h: &Harness,
    marker_path: &Path,
    ratification: BundleSigningRatificationV2,
    ratified: qbind_ledger::RatifiedBundleSigningKeyV2,
    now_unix_secs: u64,
) -> ProductionV2MarkerCoordinator {
    ProductionV2MarkerCoordinator::new(
        marker_path.to_path_buf(),
        h.env,
        h.env.chain_id(),
        runtime_genesis_hash_hex(h),
        ratification,
        ratified,
        AuthorityStateUpdateSource::ReloadApply,
        now_unix_secs,
    )
}

/// Pre-persist a v2 marker on disk (used to prime conflict tests). Uses
/// the production coordinator's first-write path so the persisted marker
/// is byte-identical to what production would write.
fn pre_persist_marker(
    h: &Harness,
    marker_path: &Path,
    ratification: BundleSigningRatificationV2,
    ratified: qbind_ledger::RatifiedBundleSigningKeyV2,
) {
    let mut c = prod_marker(h, marker_path, ratification, ratified, 50);
    c.decide_pre_apply().expect("prime: decide accepts first write");
    c.persist_after_commit().expect("prime: persist first marker");
}

fn shared_queue(policy: PeerDrivenStagingPolicy) -> SharedQueue {
    Arc::new(PlMutex::new(PeerCandidateStagingQueue::new(policy)))
}

/// Stage a validated candidate THROUGH the shared queue handle, mirroring
/// exactly what the live inbound `0x05` staging hook does
/// (`LivePeerCandidateWireDispatcher::maybe_stage_after_validation` locks
/// the shared `Arc<Mutex<…>>` and calls the staging API).
fn stage_into_shared(
    queue: &SharedQueue,
    h: &Harness,
    candidate_path: &Path,
    seq_path: Option<&Path>,
    peer_id: Option<&str>,
    staged_at: u64,
    authority_marker_digest: Option<String>,
) -> ValidatedCandidate {
    let validated = validate_candidate_bundle(reload_inputs(h, candidate_path, seq_path))
        .expect("baseline validation must succeed for staging");
    let vpc = ValidatedPeerCandidate {
        validated: validated.clone(),
        peer_id: peer_id.map(|s| s.to_string()),
    };
    let outcome = queue
        .lock()
        .try_stage_validated(&vpc, authority_marker_digest, staged_at);
    assert!(
        matches!(outcome, StagingOutcome::Staged { .. }),
        "stage must succeed; got {:?}",
        outcome
    );
    validated
}

fn marker_file_absent(marker_path: &Path) {
    assert!(
        !marker_path.exists(),
        "no authority marker file must exist at {} (no write yet)",
        marker_path.display()
    );
}

fn load_marker_v2(marker_path: &Path) -> qbind_node::pqc_authority_state::PersistentAuthorityStateRecordV2
{
    match load_authority_state_versioned(marker_path).expect("load marker") {
        Some(PersistentAuthorityStateRecordVersioned::V2(v2)) => v2,
        other => panic!("expected a persisted v2 marker, got {:?}", other),
    }
}

// =====================================================================
// A1. Shared queue visibility + no mutation before an explicit,
// enabled drain.
// =====================================================================

#[test]
fn a1_shared_queue_is_the_same_queue_the_drain_consumes() {
    let dir = tmpdir("a1-shared");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    let h = devnet_harness();
    let bundle = build_signed_bundle(&h, 5, 500);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    // The live-inbound path installs ONE shared queue handle.
    let queue = shared_queue(PeerDrivenStagingPolicy::devnet_enabled());
    let drain_view = Arc::clone(&queue);

    let validated = stage_into_shared(
        &queue,
        &h,
        &candidate_path,
        Some(&seq_path),
        Some("peer-a1"),
        1_000,
        Some("digest-a1".into()),
    );
    // A *different* clone of the same Arc sees the staged candidate.
    assert_eq!(drain_view.lock().len(), 1, "drain sees the staged candidate");

    // A disabled drain must not mutate the shared queue.
    let ctx = FakeCtx::new("aaaaaaaa");
    let mut builder = prod_builder(&h, &candidate_path, Some(&seq_path), ctx, "aaaaaaaa", Some(3), 1_001);
    let ratification = build_ratification(&h, 5);
    let ratified = ratified_v2(&h, &ratification);
    let mut marker = prod_marker(&h, &marker_path, ratification, ratified, 1_001);
    let drain = PeerDrivenApplyDrain::new();
    let disabled = try_drain_once_shared(
        &drain,
        &drain_view,
        &mut builder,
        &mut marker,
        &PeerDrivenDrainPolicy::default(),
        &PeerDrivenApplyPolicy::default(),
        &runtime_domain(&h),
        1_001,
    );
    assert!(matches!(disabled, PeerDrivenDrainOutcome::Disabled));
    assert_eq!(queue.lock().len(), 1, "disabled drain must not mutate queue");
    marker_file_absent(&marker_path);

    // An enabled drain consumes the candidate from the shared queue.
    let applied = try_drain_once_shared(
        &drain,
        &drain_view,
        &mut builder,
        &mut marker,
        &PeerDrivenDrainPolicy::devnet_enabled(),
        &PeerDrivenApplyPolicy::devnet_enabled(),
        &runtime_domain(&h),
        1_002,
    );
    match &applied {
        PeerDrivenDrainOutcome::Applied { sequence, fingerprint_prefix, .. } => {
            assert_eq!(*sequence, 5);
            assert_eq!(fingerprint_prefix, &validated.fingerprint_prefix);
        }
        other => panic!("expected Applied, got {:?}", other),
    }
    assert_eq!(queue.lock().len(), 0, "drained candidate removed from shared queue");
}

// =====================================================================
// A2. DevNet: production builder constructs a real invocation (no write
// during build), and the drain applies end-to-end, persisting a real v2
// marker after commit.
// =====================================================================

#[test]
fn a2_devnet_production_builder_and_marker_apply_end_to_end() {
    let dir = tmpdir("a2-devnet");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    let h = devnet_harness();
    let bundle = build_signed_bundle(&h, 5, 500);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let queue = shared_queue(PeerDrivenStagingPolicy::devnet_enabled());
    let _v = stage_into_shared(
        &queue, &h, &candidate_path, Some(&seq_path), Some("peer-a2"), 1_000,
        Some("digest-a2".into()),
    );

    // Sub-assertion: building an invocation performs NO disk write.
    {
        let staged = queue.lock().entries()[0].clone();
        let ctx = FakeCtx::new("aaaaaaaa");
        let mut probe = prod_builder(&h, &candidate_path, Some(&seq_path), ctx, "aaaaaaaa", Some(3), 1_001);
        use qbind_node::pqc_peer_candidate_drain::PeerDrivenDrainInvocationBuilder;
        let inv = probe.build_for(&staged).expect("production builder constructs invocation");
        drop(inv);
        marker_file_absent(&marker_path);
        assert!(!seq_path.exists(), "build must not write the sequence file");
    }

    // Now drive the full drain.
    let ctx = FakeCtx::new("aaaaaaaa");
    let mut builder = prod_builder(&h, &candidate_path, Some(&seq_path), ctx, "aaaaaaaa", Some(3), 1_001);
    let ratification = build_ratification(&h, 5);
    let ratified = ratified_v2(&h, &ratification);
    let mut marker = prod_marker(&h, &marker_path, ratification, ratified, 1_001);
    let drain = PeerDrivenApplyDrain::new();
    let outcome = try_drain_once_shared(
        &drain,
        &queue,
        &mut builder,
        &mut marker,
        &PeerDrivenDrainPolicy::devnet_enabled(),
        &PeerDrivenApplyPolicy::devnet_enabled(),
        &runtime_domain(&h),
        1_002,
    );
    match &outcome {
        PeerDrivenDrainOutcome::Applied { marker_persisted, sequence, .. } => {
            assert_eq!(*sequence, 5);
            assert!(*marker_persisted, "production v2 marker persisted after commit");
        }
        other => panic!("expected Applied, got {:?}", other),
    }
    // The production marker coordinator wrote a real v2 marker.
    let v2 = load_marker_v2(&marker_path);
    assert_eq!(v2.latest_authority_domain_sequence, 5);
    assert_eq!(queue.lock().len(), 0);
}

// =====================================================================
// A3. TestNet acceptance under an explicit TestNet policy / TestNet
// candidate. No MainNet inference.
// =====================================================================

#[test]
fn a3_testnet_production_builder_and_marker_apply_under_testnet_policy() {
    let dir = tmpdir("a3-testnet");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    let h = harness(NetworkEnvironment::Testnet);
    let bundle = build_signed_bundle(&h, 9, 900);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let queue = shared_queue(PeerDrivenStagingPolicy::testnet_enabled());
    let _v = stage_into_shared(
        &queue, &h, &candidate_path, Some(&seq_path), Some("peer-a3"), 1_000,
        Some("digest-a3".into()),
    );

    let ctx = FakeCtx::new("aaaaaaaa");
    let mut builder = prod_builder(&h, &candidate_path, Some(&seq_path), ctx, "aaaaaaaa", Some(3), 1_001);
    let ratification = build_ratification(&h, 9);
    let ratified = ratified_v2(&h, &ratification);
    let mut marker = prod_marker(&h, &marker_path, ratification, ratified, 1_001);
    let drain = PeerDrivenApplyDrain::new();
    let outcome = try_drain_once_shared(
        &drain,
        &queue,
        &mut builder,
        &mut marker,
        &PeerDrivenDrainPolicy::testnet_enabled(),
        &PeerDrivenApplyPolicy::testnet_enabled(),
        &runtime_domain(&h),
        1_002,
    );
    match &outcome {
        PeerDrivenDrainOutcome::Applied { sequence, marker_persisted, .. } => {
            assert_eq!(*sequence, 9);
            assert!(*marker_persisted);
        }
        other => panic!("expected Applied (TestNet), got {:?}", other),
    }
    let v2 = load_marker_v2(&marker_path);
    assert_eq!(v2.latest_authority_domain_sequence, 9);
}

// =====================================================================
// A4. Routes through Run 150 → Run 148 → Run 070 in strict order.
// =====================================================================

#[test]
fn a4_routes_through_run150_run148_run070_in_strict_order() {
    let dir = tmpdir("a4-route");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    let h = devnet_harness();
    let bundle = build_signed_bundle(&h, 5, 500);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let queue = shared_queue(PeerDrivenStagingPolicy::devnet_enabled());
    let _v = stage_into_shared(
        &queue, &h, &candidate_path, Some(&seq_path), Some("peer-a4"), 1_000,
        Some("digest-a4".into()),
    );

    let ctx = FakeCtx::new("aaaaaaaa");
    let timeline = ctx.timeline();
    let mut builder = prod_builder(&h, &candidate_path, Some(&seq_path), ctx, "aaaaaaaa", Some(3), 1_001);
    let ratification = build_ratification(&h, 5);
    let ratified = ratified_v2(&h, &ratification);
    let mut marker = prod_marker(&h, &marker_path, ratification, ratified, 1_001);
    let drain = PeerDrivenApplyDrain::new();
    let outcome = try_drain_once_shared(
        &drain, &queue, &mut builder, &mut marker,
        &PeerDrivenDrainPolicy::devnet_enabled(),
        &PeerDrivenApplyPolicy::devnet_enabled(),
        &runtime_domain(&h),
        1_002,
    );
    assert!(outcome.is_applied());
    assert_eq!(
        timeline.lock().unwrap().clone(),
        vec![
            "snapshot_active",
            "swap_trust_state",
            "evict_sessions",
            "commit_sequence",
        ],
        "Run 070 ordering must be snapshot → swap → evict → commit"
    );
}

// =====================================================================
// A5. The marker persist happens strictly AFTER commit (unified ordered
// timeline). Uses a timeline-sharing marker double so decide / persist
// interleave with the Run 070 callbacks in one vector.
// =====================================================================

#[test]
fn a5_marker_persist_is_strictly_after_commit_sequence() {
    let dir = tmpdir("a5-order");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_harness();
    let bundle = build_signed_bundle(&h, 5, 500);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let queue = shared_queue(PeerDrivenStagingPolicy::devnet_enabled());
    let _v = stage_into_shared(
        &queue, &h, &candidate_path, Some(&seq_path), Some("peer-a5"), 1_000,
        Some("digest-a5".into()),
    );

    let timeline = Arc::new(Mutex::new(Vec::new()));
    let ctx = FakeCtx::with_timeline("aaaaaaaa", Arc::clone(&timeline));
    let mut builder = prod_builder(&h, &candidate_path, Some(&seq_path), ctx, "aaaaaaaa", Some(3), 1_001);
    let mut marker = MockMarker::with_timeline(Arc::clone(&timeline));
    let drain = PeerDrivenApplyDrain::new();
    let outcome = try_drain_once_shared(
        &drain, &queue, &mut builder, &mut marker,
        &PeerDrivenDrainPolicy::devnet_enabled(),
        &PeerDrivenApplyPolicy::devnet_enabled(),
        &runtime_domain(&h),
        1_002,
    );
    assert!(outcome.is_applied());
    assert_eq!(
        timeline.lock().unwrap().clone(),
        vec![
            "decide_pre_apply",
            "snapshot_active",
            "swap_trust_state",
            "evict_sessions",
            "commit_sequence",
            "persist_after_commit",
        ],
        "marker decide BEFORE Run 070; marker persist STRICTLY AFTER commit"
    );
}

// =====================================================================
// A6. A second drain after a successful apply cannot double-apply.
// =====================================================================

#[test]
fn a6_second_drain_cannot_double_apply() {
    let dir = tmpdir("a6-once");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    let h = devnet_harness();
    let bundle = build_signed_bundle(&h, 5, 500);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let queue = shared_queue(PeerDrivenStagingPolicy::devnet_enabled());
    let _v = stage_into_shared(
        &queue, &h, &candidate_path, Some(&seq_path), Some("peer-a6"), 1_000,
        Some("digest-a6".into()),
    );

    let drain = PeerDrivenApplyDrain::new();

    // First drain: Applied.
    let ctx = FakeCtx::new("aaaaaaaa");
    let mut builder = prod_builder(&h, &candidate_path, Some(&seq_path), ctx, "aaaaaaaa", Some(3), 1_001);
    let r = build_ratification(&h, 5);
    let rd = ratified_v2(&h, &r);
    let mut marker = prod_marker(&h, &marker_path, r, rd, 1_001);
    let first = try_drain_once_shared(
        &drain, &queue, &mut builder, &mut marker,
        &PeerDrivenDrainPolicy::devnet_enabled(),
        &PeerDrivenApplyPolicy::devnet_enabled(),
        &runtime_domain(&h),
        1_002,
    );
    assert!(first.is_applied());
    assert_eq!(queue.lock().len(), 0);

    // Second drain on the now-empty shared queue: NoCandidate; the
    // Run 070 pipeline is never invoked again.
    let ctx2 = FakeCtx::new("zzzzzzzz");
    let timeline2 = ctx2.timeline();
    let mut builder2 = prod_builder(&h, &candidate_path, Some(&seq_path), ctx2, "aaaaaaaa", Some(3), 1_003);
    let r2 = build_ratification(&h, 5);
    let rd2 = ratified_v2(&h, &r2);
    let mut marker2 = prod_marker(&h, &marker_path, r2, rd2, 1_003);
    let second = try_drain_once_shared(
        &drain, &queue, &mut builder2, &mut marker2,
        &PeerDrivenDrainPolicy::devnet_enabled(),
        &PeerDrivenApplyPolicy::devnet_enabled(),
        &runtime_domain(&h),
        1_003,
    );
    assert!(matches!(second, PeerDrivenDrainOutcome::NoCandidate));
    assert!(timeline2.lock().unwrap().is_empty(), "no second Run 070 apply");
}

// =====================================================================
// A7. The concurrency guard prevents a re-entrant drain.
// =====================================================================

#[test]
fn a7_concurrency_guard_prevents_reentrant_drain() {
    let dir = tmpdir("a7-conc");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    let h = devnet_harness();
    let bundle = build_signed_bundle(&h, 5, 500);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let queue = shared_queue(PeerDrivenStagingPolicy::devnet_enabled());
    let _v = stage_into_shared(
        &queue, &h, &candidate_path, Some(&seq_path), Some("peer-a7"), 1_000,
        Some("digest-a7".into()),
    );

    let ctx = FakeCtx::new("aaaaaaaa");
    let timeline = ctx.timeline();
    let mut builder = prod_builder(&h, &candidate_path, Some(&seq_path), ctx, "aaaaaaaa", Some(3), 1_001);
    let r = build_ratification(&h, 5);
    let rd = ratified_v2(&h, &r);
    let mut marker = prod_marker(&h, &marker_path, r, rd, 1_001);
    let drain = PeerDrivenApplyDrain::new();

    // Simulate a concurrent in-flight drain by pre-holding the guard.
    let flag = drain.in_progress_flag();
    flag.store(true, Ordering::Release);
    let blocked = try_drain_once_shared(
        &drain, &queue, &mut builder, &mut marker,
        &PeerDrivenDrainPolicy::devnet_enabled(),
        &PeerDrivenApplyPolicy::devnet_enabled(),
        &runtime_domain(&h),
        1_002,
    );
    assert!(matches!(blocked, PeerDrivenDrainOutcome::AlreadyInProgress));
    assert!(timeline.lock().unwrap().is_empty(), "no Run 070 apply while blocked");
    assert_eq!(queue.lock().len(), 1);
    marker_file_absent(&marker_path);

    // Release: a subsequent trigger proceeds.
    flag.store(false, Ordering::Release);
    let ok = try_drain_once_shared(
        &drain, &queue, &mut builder, &mut marker,
        &PeerDrivenDrainPolicy::devnet_enabled(),
        &PeerDrivenApplyPolicy::devnet_enabled(),
        &runtime_domain(&h),
        1_003,
    );
    assert!(ok.is_applied(), "after guard release, drain proceeds; got {:?}", ok);
}

// =====================================================================
// R1. Disabled policy → no mutation.
// =====================================================================

#[test]
fn r1_disabled_policy_no_mutation() {
    let dir = tmpdir("r1-disabled");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    let h = devnet_harness();
    let bundle = build_signed_bundle(&h, 5, 500);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let queue = shared_queue(PeerDrivenStagingPolicy::devnet_enabled());
    let _v = stage_into_shared(
        &queue, &h, &candidate_path, Some(&seq_path), Some("peer-r1"), 1_000,
        Some("digest-r1".into()),
    );

    let ctx = FakeCtx::new("aaaaaaaa");
    let timeline = ctx.timeline();
    let mut builder = prod_builder(&h, &candidate_path, Some(&seq_path), ctx, "aaaaaaaa", Some(3), 1_001);
    let r = build_ratification(&h, 5);
    let rd = ratified_v2(&h, &r);
    let mut marker = prod_marker(&h, &marker_path, r, rd, 1_001);
    let drain = PeerDrivenApplyDrain::new();
    let outcome = try_drain_once_shared(
        &drain, &queue, &mut builder, &mut marker,
        &PeerDrivenDrainPolicy::default(),
        &PeerDrivenApplyPolicy::default(),
        &runtime_domain(&h),
        1_002,
    );
    assert!(matches!(outcome, PeerDrivenDrainOutcome::Disabled));
    assert!(timeline.lock().unwrap().is_empty());
    assert_eq!(queue.lock().len(), 1);
    marker_file_absent(&marker_path);
    assert!(!seq_path.exists());
}

// =====================================================================
// R2. MainNet → refused before the queue is consulted.
// =====================================================================

#[test]
fn r2_mainnet_refused_before_queue_consulted() {
    let dir = tmpdir("r2-mainnet");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    let h = devnet_harness();
    let bundle = build_signed_bundle(&h, 5, 500);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let queue = shared_queue(PeerDrivenStagingPolicy::devnet_enabled());
    let _v = stage_into_shared(
        &queue, &h, &candidate_path, Some(&seq_path), Some("peer-r2"), 1_000,
        Some("digest-r2".into()),
    );

    let ctx = FakeCtx::new("aaaaaaaa");
    let timeline = ctx.timeline();
    let mut builder = prod_builder(&h, &candidate_path, Some(&seq_path), ctx, "aaaaaaaa", Some(3), 1_001);
    let r = build_ratification(&h, 5);
    let rd = ratified_v2(&h, &r);
    let mut marker = prod_marker(&h, &marker_path, r, rd, 1_001);
    let drain = PeerDrivenApplyDrain::new();
    let outcome = try_drain_once_shared(
        &drain, &queue, &mut builder, &mut marker,
        &PeerDrivenDrainPolicy::mainnet_attempted(),
        &PeerDrivenApplyPolicy::mainnet_attempted(),
        &mainnet_runtime_domain(),
        1_002,
    );
    assert!(matches!(outcome, PeerDrivenDrainOutcome::MainNetRefused));
    assert!(outcome.is_pre_controller_refusal());
    assert!(timeline.lock().unwrap().is_empty());
    assert_eq!(queue.lock().len(), 1, "queue not consulted on MainNet refusal");
    marker_file_absent(&marker_path);
}

// =====================================================================
// R3. Empty shared queue → NoCandidate.
// =====================================================================

#[test]
fn r3_empty_shared_queue_no_candidate() {
    let dir = tmpdir("r3-empty");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    let h = devnet_harness();
    let bundle = build_signed_bundle(&h, 5, 500);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let queue = shared_queue(PeerDrivenStagingPolicy::devnet_enabled());

    let ctx = FakeCtx::new("aaaaaaaa");
    let timeline = ctx.timeline();
    let mut builder = prod_builder(&h, &candidate_path, Some(&seq_path), ctx, "aaaaaaaa", Some(3), 1_001);
    let r = build_ratification(&h, 5);
    let rd = ratified_v2(&h, &r);
    let mut marker = prod_marker(&h, &marker_path, r, rd, 1_001);
    let drain = PeerDrivenApplyDrain::new();
    let outcome = try_drain_once_shared(
        &drain, &queue, &mut builder, &mut marker,
        &PeerDrivenDrainPolicy::devnet_enabled(),
        &PeerDrivenApplyPolicy::devnet_enabled(),
        &runtime_domain(&h),
        1_002,
    );
    assert!(matches!(outcome, PeerDrivenDrainOutcome::NoCandidate));
    assert!(timeline.lock().unwrap().is_empty());
    marker_file_absent(&marker_path);
}

// =====================================================================
// R4. Expired staged candidate → not selected; no mutation.
// =====================================================================

#[test]
fn r4_expired_candidate_not_selected() {
    let dir = tmpdir("r4-expired");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    let h = devnet_harness();
    let bundle = build_signed_bundle(&h, 5, 500);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let queue = shared_queue({
        let mut sp = PeerDrivenStagingPolicy::devnet_enabled();
        sp.ttl_secs = u64::MAX;
        sp
    });
    let _v = stage_into_shared(
        &queue, &h, &candidate_path, Some(&seq_path), Some("peer-r4"), 1_000,
        Some("digest-r4".into()),
    );

    let ctx = FakeCtx::new("aaaaaaaa");
    let timeline = ctx.timeline();
    let mut builder = prod_builder(&h, &candidate_path, Some(&seq_path), ctx, "aaaaaaaa", Some(3), 5_000);
    let r = build_ratification(&h, 5);
    let rd = ratified_v2(&h, &r);
    let mut marker = prod_marker(&h, &marker_path, r, rd, 5_000);
    let mut drain_policy = PeerDrivenDrainPolicy::devnet_enabled();
    drain_policy.max_candidate_age_secs = 10;
    let drain = PeerDrivenApplyDrain::new();
    let outcome = try_drain_once_shared(
        &drain, &queue, &mut builder, &mut marker,
        &drain_policy,
        &PeerDrivenApplyPolicy::devnet_enabled(),
        &runtime_domain(&h),
        5_000,
    );
    assert!(matches!(outcome, PeerDrivenDrainOutcome::NoCandidate));
    assert!(timeline.lock().unwrap().is_empty());
    marker_file_absent(&marker_path);
}

// =====================================================================
// R5. Lower-sequence candidate vs persisted higher-sequence v2 marker →
// real CandidateMarkerConflict; no Run 070; marker bytes preserved.
// =====================================================================

#[test]
fn r5_lower_sequence_real_marker_conflict_no_run070() {
    let dir = tmpdir("r5-lower");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    let h = devnet_harness();
    let bundle = build_signed_bundle(&h, 5, 500);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    // Pre-persist a HIGHER-sequence (10) v2 marker.
    let prime = build_ratification(&h, 10);
    let prime_rd = ratified_v2(&h, &prime);
    pre_persist_marker(&h, &marker_path, prime, prime_rd);
    let marker_before = std::fs::read(&marker_path).expect("read primed marker");

    let queue = shared_queue(PeerDrivenStagingPolicy::devnet_enabled());
    let _v = stage_into_shared(
        &queue, &h, &candidate_path, Some(&seq_path), Some("peer-r5"), 1_000,
        Some("digest-r5".into()),
    );

    let ctx = FakeCtx::new("aaaaaaaa");
    let timeline = ctx.timeline();
    let mut builder = prod_builder(&h, &candidate_path, Some(&seq_path), ctx, "aaaaaaaa", Some(3), 1_001);
    // Drain coordinator ratification sequence (5) is LOWER than the
    // persisted marker (10) → real rollback refusal.
    let r = build_ratification(&h, 5);
    let rd = ratified_v2(&h, &r);
    let mut marker = prod_marker(&h, &marker_path, r, rd, 1_001);
    let drain = PeerDrivenApplyDrain::new();
    let outcome = try_drain_once_shared(
        &drain, &queue, &mut builder, &mut marker,
        &PeerDrivenDrainPolicy::devnet_enabled(),
        &PeerDrivenApplyPolicy::devnet_enabled(),
        &runtime_domain(&h),
        1_002,
    );
    assert!(matches!(outcome, PeerDrivenDrainOutcome::CandidateMarkerConflict { .. }));
    assert!(timeline.lock().unwrap().is_empty(), "no Run 070 apply");
    let marker_after = std::fs::read(&marker_path).expect("read marker after");
    assert_eq!(marker_before, marker_after, "persisted marker must be untouched");
    assert_eq!(queue.lock().len(), 1, "conflict leaves queue for reconciliation");
}

// =====================================================================
// R6. Same-sequence different-digest equivocation vs persisted v2
// marker → real CandidateMarkerConflict; no Run 070.
// =====================================================================

#[test]
fn r6_same_sequence_different_digest_real_marker_conflict() {
    let dir = tmpdir("r6-equiv");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    let h = devnet_harness();
    let bundle = build_signed_bundle(&h, 5, 500);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    // Pre-persist a marker at seq=5 ratifying the REAL signing key.
    let prime = build_ratification_for(&h, 5, &h.signing_pk);
    let prime_rd = ratified_v2(&h, &prime);
    pre_persist_marker(&h, &marker_path, prime, prime_rd);
    let marker_before = std::fs::read(&marker_path).expect("read primed marker");

    let queue = shared_queue(PeerDrivenStagingPolicy::devnet_enabled());
    let _v = stage_into_shared(
        &queue, &h, &candidate_path, Some(&seq_path), Some("peer-r6"), 1_000,
        Some("digest-r6".into()),
    );

    let ctx = FakeCtx::new("aaaaaaaa");
    let timeline = ctx.timeline();
    let mut builder = prod_builder(&h, &candidate_path, Some(&seq_path), ctx, "aaaaaaaa", Some(3), 1_001);
    // Same seq (5) but ratifying a DIFFERENT signing key → conflicting
    // digest at the same authority_domain_sequence.
    let r = build_ratification_for(&h, 5, &h.alt_signing_pk);
    let rd = ratified_v2(&h, &r);
    let mut marker = prod_marker(&h, &marker_path, r, rd, 1_001);
    let drain = PeerDrivenApplyDrain::new();
    let outcome = try_drain_once_shared(
        &drain, &queue, &mut builder, &mut marker,
        &PeerDrivenDrainPolicy::devnet_enabled(),
        &PeerDrivenApplyPolicy::devnet_enabled(),
        &runtime_domain(&h),
        1_002,
    );
    assert!(matches!(outcome, PeerDrivenDrainOutcome::CandidateMarkerConflict { .. }));
    assert!(timeline.lock().unwrap().is_empty(), "no Run 070 apply");
    let marker_after = std::fs::read(&marker_path).expect("read marker after");
    assert_eq!(marker_before, marker_after, "persisted marker must be untouched");
}

// =====================================================================
// R7. Bad-signature on-disk bundle → Run 070 validation refuses before
// swap. (The staging queue only admits validated candidates, so we
// tamper the on-disk bundle AFTER staging; Run 070 re-reads it at apply
// and fail-closes.)
// =====================================================================

#[test]
fn r7_bad_signature_on_disk_bundle_rejected_before_swap() {
    let dir = tmpdir("r7-badsig");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    let h = devnet_harness();
    let bundle = build_signed_bundle(&h, 5, 500);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let queue = shared_queue(PeerDrivenStagingPolicy::devnet_enabled());
    let _v = stage_into_shared(
        &queue, &h, &candidate_path, Some(&seq_path), Some("peer-r7"), 1_000,
        Some("digest-r7".into()),
    );

    // Tamper the signature on disk (flip the recorded signature bytes).
    let mut tampered = bundle.clone();
    if let Some(sig) = tampered.signature.as_mut() {
        let mut bytes = sig.sig_bytes.clone().into_bytes();
        if let Some(b) = bytes.get_mut(0) {
            *b = if *b == b'a' { b'b' } else { b'a' };
        }
        sig.sig_bytes = String::from_utf8(bytes).unwrap();
    }
    write_bundle_to_disk(&dir, "cand.json", &tampered);

    let ctx = FakeCtx::new("aaaaaaaa");
    let timeline = ctx.timeline();
    let mut builder = prod_builder(&h, &candidate_path, Some(&seq_path), ctx, "aaaaaaaa", Some(3), 1_001);
    let r = build_ratification(&h, 5);
    let rd = ratified_v2(&h, &r);
    let mut marker = prod_marker(&h, &marker_path, r, rd, 1_001);
    let drain = PeerDrivenApplyDrain::new();
    let outcome = try_drain_once_shared(
        &drain, &queue, &mut builder, &mut marker,
        &PeerDrivenDrainPolicy::devnet_enabled(),
        &PeerDrivenApplyPolicy::devnet_enabled(),
        &runtime_domain(&h),
        1_002,
    );
    match &outcome {
        PeerDrivenDrainOutcome::ApplyRejected { inner, .. } => {
            assert!(matches!(inner, PeerDrivenApplyOutcome::ApplyRejected { .. }));
        }
        other => panic!("expected ApplyRejected (bad signature), got {:?}", other),
    }
    let ev = timeline.lock().unwrap().clone();
    assert!(!ev.contains(&"swap_trust_state".to_string()), "no swap on bad sig");
    marker_file_absent(&marker_path);
}

// =====================================================================
// R8. Wrong-domain staged candidate → not selected; no mutation.
// =====================================================================

#[test]
fn r8_wrong_domain_candidate_not_selected() {
    let dir = tmpdir("r8-domain");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    // DevNet-signed candidate, TestNet runtime → domain mismatch.
    let dh = devnet_harness();
    let bundle = build_signed_bundle(&dh, 5, 500);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let queue = shared_queue(PeerDrivenStagingPolicy::devnet_enabled());
    let _v = stage_into_shared(
        &queue, &dh, &candidate_path, Some(&seq_path), Some("peer-r8"), 1_000,
        Some("digest-r8".into()),
    );

    let th = harness(NetworkEnvironment::Testnet);
    let ctx = FakeCtx::new("aaaaaaaa");
    let timeline = ctx.timeline();
    let mut builder = prod_builder(&th, &candidate_path, Some(&seq_path), ctx, "aaaaaaaa", Some(3), 1_001);
    let r = build_ratification(&th, 5);
    let rd = ratified_v2(&th, &r);
    let mut marker = prod_marker(&th, &marker_path, r, rd, 1_001);
    let drain = PeerDrivenApplyDrain::new();
    let outcome = try_drain_once_shared(
        &drain, &queue, &mut builder, &mut marker,
        &PeerDrivenDrainPolicy::testnet_enabled(),
        &PeerDrivenApplyPolicy::testnet_enabled(),
        &runtime_domain(&th),
        1_002,
    );
    assert!(matches!(outcome, PeerDrivenDrainOutcome::NoCandidate));
    assert!(timeline.lock().unwrap().is_empty());
    assert_eq!(queue.lock().len(), 1, "wrong-domain candidate left in queue");
    marker_file_absent(&marker_path);
}

// =====================================================================
// R9. Missing v2 marker digest (ambiguous v1+v2) → production builder
// fail-closes before apply.
// =====================================================================

#[test]
fn r9_missing_v2_digest_builder_fail_closed() {
    let dir = tmpdir("r9-novdigest");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    let h = devnet_harness();
    let bundle = build_signed_bundle(&h, 5, 500);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let queue = shared_queue(PeerDrivenStagingPolicy::devnet_enabled());
    // Stage WITHOUT a v2 authority_marker_digest.
    let _v = stage_into_shared(
        &queue, &h, &candidate_path, Some(&seq_path), Some("peer-r9"), 1_000, None,
    );

    let ctx = FakeCtx::new("aaaaaaaa");
    let timeline = ctx.timeline();
    // require_v2_marker_digest defaults to true.
    let mut builder = prod_builder(&h, &candidate_path, Some(&seq_path), ctx, "aaaaaaaa", Some(3), 1_001);
    let r = build_ratification(&h, 5);
    let rd = ratified_v2(&h, &r);
    let mut marker = prod_marker(&h, &marker_path, r, rd, 1_001);
    let drain = PeerDrivenApplyDrain::new();
    let outcome = try_drain_once_shared(
        &drain, &queue, &mut builder, &mut marker,
        &PeerDrivenDrainPolicy::devnet_enabled(),
        &PeerDrivenApplyPolicy::devnet_enabled(),
        &runtime_domain(&h),
        1_002,
    );
    match &outcome {
        PeerDrivenDrainOutcome::CandidateRejectedBeforeApply { reason, .. } => {
            assert!(reason.contains("v2"), "reason should cite missing v2 material: {}", reason);
        }
        other => panic!("expected CandidateRejectedBeforeApply, got {:?}", other),
    }
    assert!(timeline.lock().unwrap().is_empty());
    marker_file_absent(&marker_path);
    // Builder refusal is treated as possibly-transient → queue preserved.
    assert_eq!(queue.lock().len(), 1);
}

// =====================================================================
// R10. Corrupted local marker → real CandidateMarkerConflict; corrupt
// bytes preserved (never repaired).
// =====================================================================

#[test]
fn r10_corrupted_local_marker_conflict_bytes_preserved() {
    let dir = tmpdir("r10-corrupt");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    let h = devnet_harness();
    let bundle = build_signed_bundle(&h, 5, 500);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    // Write a corrupt marker file.
    if let Some(parent) = marker_path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    let garbage = b"{ this is not a valid authority marker record ]]]".to_vec();
    std::fs::write(&marker_path, &garbage).unwrap();

    let queue = shared_queue(PeerDrivenStagingPolicy::devnet_enabled());
    let _v = stage_into_shared(
        &queue, &h, &candidate_path, Some(&seq_path), Some("peer-r10"), 1_000,
        Some("digest-r10".into()),
    );

    let ctx = FakeCtx::new("aaaaaaaa");
    let timeline = ctx.timeline();
    let mut builder = prod_builder(&h, &candidate_path, Some(&seq_path), ctx, "aaaaaaaa", Some(3), 1_001);
    let r = build_ratification(&h, 5);
    let rd = ratified_v2(&h, &r);
    let mut marker = prod_marker(&h, &marker_path, r, rd, 1_001);
    let drain = PeerDrivenApplyDrain::new();
    let outcome = try_drain_once_shared(
        &drain, &queue, &mut builder, &mut marker,
        &PeerDrivenDrainPolicy::devnet_enabled(),
        &PeerDrivenApplyPolicy::devnet_enabled(),
        &runtime_domain(&h),
        1_002,
    );
    assert!(matches!(outcome, PeerDrivenDrainOutcome::CandidateMarkerConflict { .. }));
    assert!(timeline.lock().unwrap().is_empty(), "no Run 070 apply on corrupt marker");
    let after = std::fs::read(&marker_path).expect("read marker after");
    assert_eq!(after, garbage, "corrupt marker must never be repaired/overwritten");
}

// =====================================================================
// R11. Run 070 validation failure before swap → no mutation. A
// pre-seeded sequence-persistence record at a HIGHER sequence than the
// candidate makes the Run 070 anti-rollback check fail before any state
// swap.
// =====================================================================

#[test]
fn r11_run070_validation_failure_before_swap() {
    let dir = tmpdir("r11-validate");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    let h = devnet_harness();
    let bundle = build_signed_bundle(&h, 5, 500);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let queue = shared_queue(PeerDrivenStagingPolicy::devnet_enabled());
    let _v = stage_into_shared(
        &queue, &h, &candidate_path, None, Some("peer-r11"), 1_000,
        Some("digest-r11".into()),
    );

    // Pre-seed the sequence persistence file at a HIGHER sequence (9)
    // than the candidate (5) → Run 070 anti-rollback refusal.
    let record = PersistentTrustBundleSequenceRecord::new(
        h.trust_env,
        chain_id_hex(h.env.chain_id()),
        9,
        "f".repeat(64),
        50,
    );
    atomic_write_record(&seq_path, &record).expect("pre-seed seq record");

    let ctx = FakeCtx::new("aaaaaaaa");
    let timeline = ctx.timeline();
    let mut builder = prod_builder(&h, &candidate_path, Some(&seq_path), ctx, "aaaaaaaa", Some(3), 1_001);
    let r = build_ratification(&h, 5);
    let rd = ratified_v2(&h, &r);
    let mut marker = prod_marker(&h, &marker_path, r, rd, 1_001);
    let drain = PeerDrivenApplyDrain::new();
    let outcome = try_drain_once_shared(
        &drain, &queue, &mut builder, &mut marker,
        &PeerDrivenDrainPolicy::devnet_enabled(),
        &PeerDrivenApplyPolicy::devnet_enabled(),
        &runtime_domain(&h),
        1_002,
    );
    assert!(
        matches!(outcome, PeerDrivenDrainOutcome::ApplyRejected { .. }),
        "expected ApplyRejected, got {:?}",
        outcome
    );
    let ev = timeline.lock().unwrap().clone();
    assert!(!ev.contains(&"swap_trust_state".to_string()), "no swap on validation failure");
    marker_file_absent(&marker_path);
}

// =====================================================================
// R12. Run 070 eviction failure → rollback; no commit; no marker.
// =====================================================================

#[test]
fn r12_eviction_failure_rollback_no_commit_no_marker() {
    let dir = tmpdir("r12-evict");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    let h = devnet_harness();
    let bundle = build_signed_bundle(&h, 5, 500);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let queue = shared_queue(PeerDrivenStagingPolicy::devnet_enabled());
    let _v = stage_into_shared(
        &queue, &h, &candidate_path, Some(&seq_path), Some("peer-r12"), 1_000,
        Some("digest-r12".into()),
    );

    let mut ctx = FakeCtx::new("aaaaaaaa");
    ctx.evict_action = ActionPlan::Err("session-eviction failed (sim)".into());
    let timeline = ctx.timeline();
    let active = ctx.active();
    let mut builder = prod_builder(&h, &candidate_path, Some(&seq_path), ctx, "aaaaaaaa", Some(2), 1_001);
    let r = build_ratification(&h, 5);
    let rd = ratified_v2(&h, &r);
    let mut marker = prod_marker(&h, &marker_path, r, rd, 1_001);
    let drain = PeerDrivenApplyDrain::new();
    let outcome = try_drain_once_shared(
        &drain, &queue, &mut builder, &mut marker,
        &PeerDrivenDrainPolicy::devnet_enabled(),
        &PeerDrivenApplyPolicy::devnet_enabled(),
        &runtime_domain(&h),
        1_002,
    );
    match &outcome {
        PeerDrivenDrainOutcome::ApplyRejected { inner, .. } => {
            assert!(matches!(inner, PeerDrivenApplyOutcome::ApplyRollbackSucceeded { .. }));
        }
        other => panic!("expected ApplyRejected, got {:?}", other),
    }
    assert_eq!(*active.lock().unwrap(), "aaaaaaaa", "live state rolled back");
    let ev = timeline.lock().unwrap().clone();
    assert!(ev.contains(&"rollback_trust_state".to_string()));
    assert!(!ev.contains(&"commit_sequence".to_string()), "no commit");
    marker_file_absent(&marker_path);
    assert!(!outcome.is_fatal_operator_actionable());
}

// =====================================================================
// R13. Run 070 commit failure → rollback; no marker persisted.
// =====================================================================

#[test]
fn r13_commit_failure_rollback_no_marker() {
    let dir = tmpdir("r13-commit");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    let h = devnet_harness();
    let bundle = build_signed_bundle(&h, 5, 500);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let queue = shared_queue(PeerDrivenStagingPolicy::devnet_enabled());
    let _v = stage_into_shared(
        &queue, &h, &candidate_path, Some(&seq_path), Some("peer-r13"), 1_000,
        Some("digest-r13".into()),
    );

    let mut ctx = FakeCtx::new("aaaaaaaa");
    ctx.commit_action = ActionPlan::Err("commit-sim".into());
    let active = ctx.active();
    let mut builder = prod_builder(&h, &candidate_path, Some(&seq_path), ctx, "aaaaaaaa", Some(2), 1_001);
    let r = build_ratification(&h, 5);
    let rd = ratified_v2(&h, &r);
    let mut marker = prod_marker(&h, &marker_path, r, rd, 1_001);
    let drain = PeerDrivenApplyDrain::new();
    let outcome = try_drain_once_shared(
        &drain, &queue, &mut builder, &mut marker,
        &PeerDrivenDrainPolicy::devnet_enabled(),
        &PeerDrivenApplyPolicy::devnet_enabled(),
        &runtime_domain(&h),
        1_002,
    );
    match &outcome {
        PeerDrivenDrainOutcome::ApplyRejected { inner, .. } => {
            assert!(matches!(inner, PeerDrivenApplyOutcome::ApplyRollbackSucceeded { .. }));
        }
        other => panic!("expected ApplyRejected (commit failure), got {:?}", other),
    }
    assert_eq!(*active.lock().unwrap(), "aaaaaaaa", "live state rolled back");
    // The production coordinator's persist_after_commit was never
    // reached → no marker file.
    marker_file_absent(&marker_path);
    assert!(!outcome.is_fatal_operator_actionable());
}

// =====================================================================
// R14. Marker persist failure AFTER commit → fatal / operator-
// actionable. Uses a deterministic post-commit-failure marker double.
// =====================================================================

#[test]
fn r14_marker_persist_failure_after_commit_is_fatal() {
    let dir = tmpdir("r14-fatal");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_harness();
    let bundle = build_signed_bundle(&h, 5, 500);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let queue = shared_queue(PeerDrivenStagingPolicy::devnet_enabled());
    let _v = stage_into_shared(
        &queue, &h, &candidate_path, Some(&seq_path), Some("peer-r14"), 1_000,
        Some("digest-r14".into()),
    );

    let timeline = Arc::new(Mutex::new(Vec::new()));
    let ctx = FakeCtx::with_timeline("aaaaaaaa", Arc::clone(&timeline));
    let mut builder = prod_builder(&h, &candidate_path, Some(&seq_path), ctx, "aaaaaaaa", Some(2), 1_001);
    let mut marker = MockMarker::with_timeline(Arc::clone(&timeline))
        .with_post_commit_err("marker-persist-failed-after-commit (sim)");
    let drain = PeerDrivenApplyDrain::new();
    let outcome = try_drain_once_shared(
        &drain, &queue, &mut builder, &mut marker,
        &PeerDrivenDrainPolicy::devnet_enabled(),
        &PeerDrivenApplyPolicy::devnet_enabled(),
        &runtime_domain(&h),
        1_002,
    );
    match &outcome {
        PeerDrivenDrainOutcome::ApplyFatal { inner, .. } => {
            assert!(matches!(inner, PeerDrivenApplyOutcome::MarkerPersistFailedAfterCommit { .. }));
        }
        other => panic!("expected ApplyFatal, got {:?}", other),
    }
    assert!(outcome.is_fatal_operator_actionable());
    // commit happened before the persist failure.
    let ev = timeline.lock().unwrap().clone();
    assert!(ev.contains(&"commit_sequence".to_string()));
    assert!(ev.contains(&"persist_after_commit".to_string()));
    assert_eq!(queue.lock().len(), 1, "fatal leaves queue for offline reconciliation");
}

// =====================================================================
// R15. v1/legacy path unchanged: with the v2 gate disabled the
// production builder still constructs an invocation for a no-digest
// candidate, and building performs no write.
// =====================================================================

#[test]
fn r15_v1_legacy_path_unchanged_builder_allows_no_digest_when_v2_gate_off() {
    let dir = tmpdir("r15-v1");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    let h = devnet_harness();
    let bundle = build_signed_bundle(&h, 5, 500);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let queue = shared_queue(PeerDrivenStagingPolicy::devnet_enabled());
    let _v = stage_into_shared(
        &queue, &h, &candidate_path, Some(&seq_path), Some("peer-r15"), 1_000, None,
    );
    let staged = queue.lock().entries()[0].clone();

    let ctx = FakeCtx::new("aaaaaaaa");
    let mut builder =
        prod_builder(&h, &candidate_path, Some(&seq_path), ctx, "aaaaaaaa", Some(3), 1_001)
            .with_require_v2_marker_digest(false);
    use qbind_node::pqc_peer_candidate_drain::PeerDrivenDrainInvocationBuilder;
    let inv = builder
        .build_for(&staged)
        .expect("v2 gate off → builder constructs invocation for no-digest candidate");
    drop(inv);
    marker_file_absent(&marker_path);
    assert!(!seq_path.exists(), "build must not write the sequence file");
    assert_eq!(queue.lock().len(), 1, "build does not mutate the queue");
}

// =====================================================================
// R16. Propagation-only behaviour unchanged: a non-applying drain leaves
// the staging queue entries identical.
// =====================================================================

#[test]
fn r16_propagation_only_behaviour_unchanged() {
    let dir = tmpdir("r16-prop");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    let h = devnet_harness();
    let bundle = build_signed_bundle(&h, 5, 500);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let queue = shared_queue(PeerDrivenStagingPolicy::devnet_enabled());
    let _v = stage_into_shared(
        &queue, &h, &candidate_path, Some(&seq_path), Some("peer-r16"), 1_000,
        Some("digest-r16".into()),
    );
    let entries_before = queue.lock().entries();

    let ctx = FakeCtx::new("aaaaaaaa");
    let timeline = ctx.timeline();
    let mut builder = prod_builder(&h, &candidate_path, Some(&seq_path), ctx, "aaaaaaaa", Some(3), 1_001);
    let r = build_ratification(&h, 5);
    let rd = ratified_v2(&h, &r);
    let mut marker = prod_marker(&h, &marker_path, r, rd, 1_001);
    let drain = PeerDrivenApplyDrain::new();
    let outcome = try_drain_once_shared(
        &drain, &queue, &mut builder, &mut marker,
        &PeerDrivenDrainPolicy::default(),
        &PeerDrivenApplyPolicy::default(),
        &runtime_domain(&h),
        1_002,
    );
    assert!(matches!(outcome, PeerDrivenDrainOutcome::Disabled));
    assert_eq!(queue.lock().entries(), entries_before, "queue unchanged on Disabled");
    assert!(timeline.lock().unwrap().is_empty());
    marker_file_absent(&marker_path);
}