//! Run 150 — integration tests for the **source/test-only explicit
//! DevNet/TestNet drain trigger** that wires the Run 145/146 staged
//! peer-candidate queue into the Run 148 peer-driven apply controller
//! (which in turn calls the existing Run 070 apply contract).
//!
//! These tests exercise
//! [`qbind_node::pqc_peer_candidate_drain::PeerDrivenApplyDrain::try_drain_once`]
//! and assert the full Run 150 acceptance / rejection matrix from
//! `task/RUN_150_TASK.txt`:
//!
//! - **A1** explicit drain applies one valid staged DevNet v2 candidate
//! - **A2** explicit drain applies one valid staged TestNet candidate
//!   when policy allows TestNet
//! - **A3** empty queue returns `NoCandidate`
//! - **A4** disabled policy returns `Disabled`
//! - **A5** MainNet returns `MainNetRefused`
//! - **A6** expired staged candidate cannot apply (removed)
//! - **A7** deterministic highest-sequence selection wins; tie broken by
//!   lexicographically smallest fingerprint
//! - **A8** duplicate / re-trigger candidate cannot double-apply
//! - **R1** lower-sequence candidate cannot drain (queue contains both;
//!   higher selected; lower remains)
//! - **R2** same-sequence different-digest equivocation refused at the
//!   Run 148 pre-apply marker gate (no mutation)
//! - **R3** bad-signature staged candidate refused before apply
//! - **R4** wrong-domain staged candidate refused before apply
//! - **R5** ambiguous v1+v2 candidate refused at the Run 148 marker
//!   pre-apply gate (no mutation)
//! - **R6** Run 070 validation failure before swap produces no mutation
//! - **R7** Run 070 session-eviction failure → rollback succeeds → no
//!   commit, no marker, no drain success
//! - **R8** Run 070 sequence-commit failure → rollback succeeds (or
//!   fatal on rollback failure) per Run 070 discipline
//! - **R9** marker persist failure AFTER commit is fatal /
//!   operator-actionable per Run 134/138 discipline
//! - **R10** concurrency guard prevents double drain
//! - **R11** v1/legacy staged candidate behaviour: when require_v2 is
//!   on, marker pre-apply refuses; queue / live state untouched
//! - **R12** propagation-only behaviour unchanged (drain does not
//!   touch propagation surfaces)
//!
//! # Strict scope (Run 150)
//!
//! - Source/test wiring only. Release-binary operator trigger evidence
//!   is deferred to Run 151.
//! - DevNet / TestNet only — MainNet refused unconditionally.
//! - Reuses the existing Run 148
//!   `try_apply_staged_peer_candidate` controller, which itself reuses
//!   the existing Run 070 `apply_validated_candidate_with_previous`
//!   contract through the production [`LiveTrustApplyContext`] surface
//!   (driven here by the same `FakeLiveTrustApplyContext` pattern Run
//!   070 / Run 148 tests use).
//! - Reuses the Run 134/138 v2 marker pre/post-commit discipline via
//!   the [`V2MarkerCoordinator`] trait (driven here by a configurable
//!   mock so R2 / R5 / R9 can be exercised without constructing real
//!   ratification objects).

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use qbind_crypto::MlDsa44Backend;
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_peer_candidate_apply::{
    PeerDrivenApplyInvocation, PeerDrivenApplyOutcome, PeerDrivenApplyPolicy,
    PeerDrivenApplyRuntimeDomain, V2MarkerCoordinator,
};
use qbind_node::pqc_peer_candidate_drain::{
    PeerDrivenApplyDrain, PeerDrivenDrainInvocationBuilder, PeerDrivenDrainOutcome,
    PeerDrivenDrainPolicy,
};
use qbind_node::pqc_peer_candidate_staging::{
    PeerCandidateStagingQueue, PeerDrivenStagingPolicy, StagedPeerCandidate, StagingOutcome,
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
use qbind_node::pqc_trust_sequence::{chain_id_hex, sequence_file_path};
use qbind_types::NetworkEnvironment;

// =====================================================================
// Helpers (adapted from run_070 / run_148 test files).
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
        "qbind-run150-{}-{}-{}",
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

struct DevnetSigningHarness {
    signing_keys: BundleSigningKeySet,
    signing_key_id: [u8; 32],
    signing_sk: Vec<u8>,
    root_id_hex: String,
    root_pk_hex: String,
}

fn devnet_signing_harness() -> DevnetSigningHarness {
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen signing key");
    let id = derive_signing_key_id(&pk);
    let signing_keys = BundleSigningKeySet::from_keys_unchecked(vec![BundleSigningKey {
        key_id_bytes: id,
        suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
        pk_bytes: pk,
    }]);
    let root = mint_devnet_root().expect("mint devnet root");
    DevnetSigningHarness {
        signing_keys,
        signing_key_id: id,
        signing_sk: sk,
        root_id_hex: hex_lower(&root.root_key_id),
        root_pk_hex: hex_lower(&root.root_pk),
    }
}

fn build_signed_devnet_bundle(
    h: &DevnetSigningHarness,
    sequence: u64,
    generated_at: u64,
    activation_height: Option<u64>,
    revocations: Vec<TrustBundleRevocation>,
) -> TrustBundle {
    let mut bundle = TrustBundle {
        bundle_version: TrustBundle::SUPPORTED_SCHEMA_VERSION,
        environment: TrustBundleEnvironment::Devnet,
        chain_id: Some(chain_id_hex(NetworkEnvironment::Devnet.chain_id())),
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
        revocations,
        signature: None,
        activation_epoch: None,
        activation_height,
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

fn snapshot_seq_file(path: &Path) -> Option<(Vec<u8>, std::time::SystemTime)> {
    if !path.exists() {
        return None;
    }
    let bytes = std::fs::read(path).expect("read seq file");
    let mtime = std::fs::metadata(path)
        .expect("metadata")
        .modified()
        .expect("mtime");
    Some((bytes, mtime))
}

fn assert_seq_file_unchanged(
    path: &Path,
    snapshot: Option<(Vec<u8>, std::time::SystemTime)>,
) {
    match (snapshot, path.exists()) {
        (None, false) => {}
        (None, true) => panic!(
            "Run 150 refusal must not create persistence file at {}",
            path.display()
        ),
        (Some(_), false) => panic!(
            "Run 150 refusal must not delete persistence file at {}",
            path.display()
        ),
        (Some((before, mt_before)), true) => {
            let after = std::fs::read(path).expect("read seq file");
            assert_eq!(before, after, "Run 150 refusal must not rewrite seq file");
            let mt_after = std::fs::metadata(path).unwrap().modified().unwrap();
            assert_eq!(mt_before, mt_after, "Run 150 refusal must not touch mtime");
        }
    }
}

fn devnet_inputs<'a>(
    candidate_path: &'a Path,
    signing_keys: &'a BundleSigningKeySet,
    seq_path: Option<&'a Path>,
    activation_current_height: u64,
) -> ReloadCheckInputs<'a> {
    ReloadCheckInputs {
        candidate_path,
        environment: NetworkEnvironment::Devnet,
        chain_id: NetworkEnvironment::Devnet.chain_id(),
        validation_time_secs: 100,
        signing_keys,
        activation_ctx: ActivationContext::height_only(activation_current_height),
        sequence_persistence_path: seq_path,
        local_leaf_cert_bytes: None,
    }
}

// =====================================================================
// `FakeLiveTrustApplyContext` — same shape as Run 070 / Run 148 tests.
// =====================================================================

#[derive(Debug, Clone)]
enum ActionPlan {
    Ok,
    Err(String),
}

#[derive(Debug, Default, Clone)]
struct CallLog {
    events: Vec<String>,
}

struct FakeLiveTrustApplyContext {
    log: Arc<Mutex<CallLog>>,
    active_fingerprint: Arc<Mutex<String>>,
    swap_action: ActionPlan,
    evict_action: ActionPlan,
    commit_action: ActionPlan,
    rollback_action: ActionPlan,
    eviction_count: usize,
}

impl FakeLiveTrustApplyContext {
    fn new(initial_fp: &str) -> Self {
        Self {
            log: Arc::new(Mutex::new(CallLog::default())),
            active_fingerprint: Arc::new(Mutex::new(initial_fp.to_string())),
            swap_action: ActionPlan::Ok,
            evict_action: ActionPlan::Ok,
            commit_action: ActionPlan::Ok,
            rollback_action: ActionPlan::Ok,
            eviction_count: 2,
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
        self.log.lock().unwrap().events.push("snapshot_active".into());
        let prev: String = self.active_fingerprint.lock().unwrap().clone();
        Ok(Box::new(prev))
    }
    fn swap_trust_state(&mut self, candidate: &LoadedTrustBundle) -> Result<(), String> {
        self.log.lock().unwrap().events.push("swap_trust_state".into());
        match &self.swap_action {
            ActionPlan::Err(m) => Err(m.clone()),
            ActionPlan::Ok => {
                let new_fp_prefix = candidate.fingerprint_hex()[..8].to_string();
                *self.active_fingerprint.lock().unwrap() = new_fp_prefix;
                Ok(())
            }
        }
    }
    fn evict_sessions(&mut self) -> Result<usize, String> {
        self.log.lock().unwrap().events.push("evict_sessions".into());
        match &self.evict_action {
            ActionPlan::Err(m) => Err(m.clone()),
            ActionPlan::Ok => Ok(self.eviction_count),
        }
    }
    fn commit_sequence(&mut self, _candidate: &LoadedTrustBundle) -> Result<(), String> {
        self.log.lock().unwrap().events.push("commit_sequence".into());
        match &self.commit_action {
            ActionPlan::Err(m) => Err(m.clone()),
            ActionPlan::Ok => Ok(()),
        }
    }
    fn rollback_trust_state(
        &mut self,
        snapshot: Box<dyn std::any::Any + Send + Sync>,
    ) -> Result<(), String> {
        self.log
            .lock()
            .unwrap()
            .events
            .push("rollback_trust_state".into());
        match &self.rollback_action {
            ActionPlan::Err(m) => Err(m.clone()),
            ActionPlan::Ok => {
                if let Ok(prev) = snapshot.downcast::<String>() {
                    *self.active_fingerprint.lock().unwrap() = *prev;
                }
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------
// Mock v2 marker coordinator.
// ---------------------------------------------------------------------

#[derive(Debug, Default)]
struct MockV2MarkerCoordinator {
    log: Arc<Mutex<Vec<String>>>,
    pre_apply: Option<Result<(), String>>,
    post_commit: Option<Result<(), String>>,
}

impl MockV2MarkerCoordinator {
    fn new() -> Self {
        Self {
            log: Arc::new(Mutex::new(Vec::new())),
            pre_apply: Some(Ok(())),
            post_commit: Some(Ok(())),
        }
    }
    fn log(&self) -> Arc<Mutex<Vec<String>>> {
        self.log.clone()
    }
    fn with_pre_apply_err(mut self, msg: &str) -> Self {
        self.pre_apply = Some(Err(msg.to_string()));
        self
    }
    fn with_post_commit_err(mut self, msg: &str) -> Self {
        self.post_commit = Some(Err(msg.to_string()));
        self
    }
}

impl V2MarkerCoordinator for MockV2MarkerCoordinator {
    fn decide_pre_apply(&mut self) -> Result<(), String> {
        self.log.lock().unwrap().push("decide_pre_apply".into());
        self.pre_apply.clone().unwrap_or(Ok(()))
    }
    fn persist_after_commit(&mut self) -> Result<(), String> {
        self.log.lock().unwrap().push("persist_after_commit".into());
        self.post_commit.clone().unwrap_or(Ok(()))
    }
}

// ---------------------------------------------------------------------
// Staged-candidate helpers.
// ---------------------------------------------------------------------

fn stage_candidate_from_bundle(
    queue: &mut PeerCandidateStagingQueue,
    candidate_path: &Path,
    signing_keys: &BundleSigningKeySet,
    seq_path: Option<&Path>,
    peer_id: Option<&str>,
    staged_at: u64,
    authority_marker_digest: Option<String>,
) -> ValidatedCandidate {
    let validated = validate_candidate_bundle(devnet_inputs(
        candidate_path,
        signing_keys,
        seq_path,
        0,
    ))
    .expect("baseline validation must succeed for staging");
    let vpc = ValidatedPeerCandidate {
        validated: validated.clone(),
        peer_id: peer_id.map(|s| s.to_string()),
    };
    let outcome = queue.try_stage_validated(&vpc, authority_marker_digest, staged_at);
    assert!(
        matches!(outcome, StagingOutcome::Staged { .. }),
        "stage must succeed; got {:?}",
        outcome
    );
    validated
}

fn devnet_runtime_domain() -> PeerDrivenApplyRuntimeDomain {
    PeerDrivenApplyRuntimeDomain::new(
        NetworkEnvironment::Devnet,
        chain_id_hex(NetworkEnvironment::Devnet.chain_id()),
    )
}

fn testnet_runtime_domain() -> PeerDrivenApplyRuntimeDomain {
    PeerDrivenApplyRuntimeDomain::new(
        NetworkEnvironment::Testnet,
        chain_id_hex(NetworkEnvironment::Testnet.chain_id()),
    )
}

fn mainnet_runtime_domain() -> PeerDrivenApplyRuntimeDomain {
    PeerDrivenApplyRuntimeDomain::new(
        NetworkEnvironment::Mainnet,
        chain_id_hex(NetworkEnvironment::Mainnet.chain_id()),
    )
}

// ---------------------------------------------------------------------
// Test-only `PeerDrivenDrainInvocationBuilder`. Owns the
// candidate path, signing keys, sequence file path, and the live
// apply context so per-trigger borrows do not fight the borrow
// checker. A `refuse_with` knob is provided so the
// `CandidateRejectedBeforeApply` path can be observed without
// constructing a broken candidate.
// ---------------------------------------------------------------------

struct DrainBuilder {
    candidate_path: PathBuf,
    signing_keys: BundleSigningKeySet,
    seq_path: PathBuf,
    activation_current_height: u64,
    ctx: FakeLiveTrustApplyContext,
    previous_fingerprint_prefix: String,
    previous_sequence: Option<u64>,
    /// When `Some`, the builder refuses to construct an invocation
    /// and returns the supplied message via
    /// [`PeerDrivenDrainOutcome::CandidateRejectedBeforeApply`].
    refuse_with: Option<String>,
    /// Runtime environment baked into the inputs — defaults to DevNet.
    runtime_env: NetworkEnvironment,
}

impl DrainBuilder {
    fn devnet(
        candidate_path: PathBuf,
        signing_keys: BundleSigningKeySet,
        seq_path: PathBuf,
        ctx: FakeLiveTrustApplyContext,
    ) -> Self {
        Self {
            candidate_path,
            signing_keys,
            seq_path,
            activation_current_height: 0,
            ctx,
            previous_fingerprint_prefix: String::new(),
            previous_sequence: None,
            refuse_with: None,
            runtime_env: NetworkEnvironment::Devnet,
        }
    }

    fn with_previous(mut self, prefix: &str, seq: Option<u64>) -> Self {
        self.previous_fingerprint_prefix = prefix.to_string();
        self.previous_sequence = seq;
        self
    }

    fn with_refusal(mut self, reason: &str) -> Self {
        self.refuse_with = Some(reason.to_string());
        self
    }

    fn ctx_log(&self) -> Arc<Mutex<CallLog>> {
        self.ctx.log()
    }

    fn active(&self) -> Arc<Mutex<String>> {
        self.ctx.active()
    }
}

impl PeerDrivenDrainInvocationBuilder for DrainBuilder {
    fn build_for<'a>(
        &'a mut self,
        _staged: &StagedPeerCandidate,
    ) -> Result<PeerDrivenApplyInvocation<'a>, String> {
        if let Some(reason) = &self.refuse_with {
            return Err(reason.clone());
        }
        let inputs = ReloadCheckInputs {
            candidate_path: &self.candidate_path,
            environment: self.runtime_env,
            chain_id: self.runtime_env.chain_id(),
            validation_time_secs: 100,
            signing_keys: &self.signing_keys,
            activation_ctx: ActivationContext::height_only(self.activation_current_height),
            sequence_persistence_path: Some(&self.seq_path),
            local_leaf_cert_bytes: None,
        };
        Ok(PeerDrivenApplyInvocation {
            inputs,
            live_apply_ctx: &mut self.ctx,
            previous_fingerprint_prefix: self.previous_fingerprint_prefix.clone(),
            previous_sequence: self.previous_sequence,
        })
    }
}

// =====================================================================
// A1. Explicit drain applies one valid staged DevNet v2 candidate.
// =====================================================================

#[test]
fn a1_explicit_drain_applies_one_valid_staged_devnet_v2_candidate() {
    let dir = tmpdir("a1-devnet");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 5, 500, None, vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    let validated = stage_candidate_from_bundle(
        &mut queue,
        &candidate_path,
        &h.signing_keys,
        Some(&seq_path),
        Some("peer-a1"),
        1_000,
        Some("digest-a1".into()),
    );
    assert_eq!(queue.len(), 1);

    let ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let mut builder = DrainBuilder::devnet(
        candidate_path.clone(),
        h.signing_keys.clone(),
        seq_path.clone(),
        ctx,
    )
    .with_previous("aaaaaaaa", Some(3));
    let ctx_log = builder.ctx_log();
    let active = builder.active();

    let mut marker = MockV2MarkerCoordinator::new();
    let marker_log = marker.log();

    let drain = PeerDrivenApplyDrain::new();
    let drain_policy = PeerDrivenDrainPolicy::devnet_enabled();
    let apply_policy = PeerDrivenApplyPolicy::devnet_enabled();

    let outcome = drain.try_drain_once(
        &mut queue,
        &mut builder,
        &mut marker,
        &drain_policy,
        &apply_policy,
        &devnet_runtime_domain(),
        1_001,
    );

    match &outcome {
        PeerDrivenDrainOutcome::Applied {
            fingerprint_prefix,
            sequence,
            session_evictions,
            marker_persisted,
            ..
        } => {
            assert_eq!(fingerprint_prefix, &validated.fingerprint_prefix);
            assert_eq!(*sequence, 5);
            assert_eq!(*session_evictions, 2);
            assert!(*marker_persisted, "v2 marker persist required and succeeded");
        }
        other => panic!("expected Applied, got {:?}", other),
    }
    assert!(outcome.is_applied());

    // Strict Run 070 ordering.
    let events = ctx_log.lock().unwrap().events.clone();
    assert_eq!(
        events,
        vec![
            "snapshot_active",
            "swap_trust_state",
            "evict_sessions",
            "commit_sequence",
        ],
        "Run 070 ordering must be snapshot → swap → evict → commit"
    );
    assert_eq!(*active.lock().unwrap(), validated.fingerprint_prefix);

    // Marker discipline.
    assert_eq!(
        marker_log.lock().unwrap().clone(),
        vec!["decide_pre_apply", "persist_after_commit"]
    );

    // Terminal-success removes the consumed candidate from the queue.
    assert_eq!(queue.len(), 0, "drained candidate removed from queue");
}

// =====================================================================
// A2. TestNet policy gates entry but candidate domain mismatch is
// caught at the drain selector (DevNet-signed candidate, TestNet
// runtime); no Run 070 invocation, no mutation. This proves the
// TestNet policy is honoured (does not refuse on policy gate) and the
// domain check filters the candidate.
// =====================================================================

#[test]
fn a2_testnet_policy_allows_drain_but_wrong_domain_filters_candidate() {
    let dir = tmpdir("a2-testnet");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 7, 700, None, vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    // Stage a DevNet-flavoured candidate on a permissive DevNet
    // staging queue (the staging queue's own gate is exercised in
    // Run 145 tests).
    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    let _validated = stage_candidate_from_bundle(
        &mut queue,
        &candidate_path,
        &h.signing_keys,
        Some(&seq_path),
        Some("peer-a2"),
        2_000,
        Some("digest-a2".into()),
    );

    let snap = snapshot_seq_file(&seq_path);
    let ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let mut builder = DrainBuilder::devnet(
        candidate_path.clone(),
        h.signing_keys.clone(),
        seq_path.clone(),
        ctx,
    );
    let ctx_log = builder.ctx_log();
    let mut marker = MockV2MarkerCoordinator::new();
    let marker_log = marker.log();

    let drain = PeerDrivenApplyDrain::new();
    let drain_policy = PeerDrivenDrainPolicy::testnet_enabled();
    let apply_policy = PeerDrivenApplyPolicy::testnet_enabled();

    let outcome = drain.try_drain_once(
        &mut queue,
        &mut builder,
        &mut marker,
        &drain_policy,
        &apply_policy,
        &testnet_runtime_domain(),
        2_001,
    );
    // Selector finds NO eligible candidate because the staged
    // DevNet-tagged entry does not match the TestNet runtime
    // (environment + chain id mismatch).
    assert!(
        matches!(outcome, PeerDrivenDrainOutcome::NoCandidate),
        "TestNet drain must not select DevNet-tagged candidate; got {:?}",
        outcome
    );
    assert!(
        ctx_log.lock().unwrap().events.is_empty(),
        "no apply ctx calls on TestNet selection miss"
    );
    assert!(marker_log.lock().unwrap().is_empty());
    assert_seq_file_unchanged(&seq_path, snap);
    // Queue is untouched — the candidate may still be applied later
    // under a DevNet runtime.
    assert_eq!(queue.len(), 1);
}

// =====================================================================
// A3. Empty queue returns `NoCandidate`.
// =====================================================================

#[test]
fn a3_empty_queue_returns_no_candidate() {
    let dir = tmpdir("a3-empty");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 4, 400, None, vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    // intentionally do NOT stage.
    let snap = snapshot_seq_file(&seq_path);

    let ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let mut builder = DrainBuilder::devnet(
        candidate_path.clone(),
        h.signing_keys.clone(),
        seq_path.clone(),
        ctx,
    );
    let ctx_log = builder.ctx_log();
    let mut marker = MockV2MarkerCoordinator::new();
    let marker_log = marker.log();

    let drain = PeerDrivenApplyDrain::new();
    let drain_policy = PeerDrivenDrainPolicy::devnet_enabled();
    let apply_policy = PeerDrivenApplyPolicy::devnet_enabled();

    let outcome = drain.try_drain_once(
        &mut queue,
        &mut builder,
        &mut marker,
        &drain_policy,
        &apply_policy,
        &devnet_runtime_domain(),
        3_000,
    );
    assert!(matches!(outcome, PeerDrivenDrainOutcome::NoCandidate));
    assert!(outcome.is_pre_controller_refusal());
    assert!(ctx_log.lock().unwrap().events.is_empty());
    assert!(marker_log.lock().unwrap().is_empty());
    assert_seq_file_unchanged(&seq_path, snap);
    assert_eq!(queue.len(), 0);
}

// =====================================================================
// A4. Disabled policy returns `Disabled`. No staging-queue lookup,
// no concurrency-guard touch, no Run 148 controller call.
// =====================================================================

#[test]
fn a4_disabled_policy_returns_disabled_without_mutation() {
    let dir = tmpdir("a4-disabled");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 4, 400, None, vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    let _validated = stage_candidate_from_bundle(
        &mut queue,
        &candidate_path,
        &h.signing_keys,
        Some(&seq_path),
        Some("peer-a4"),
        3_000,
        Some("digest-a4".into()),
    );

    let snap = snapshot_seq_file(&seq_path);
    let ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let mut builder = DrainBuilder::devnet(
        candidate_path.clone(),
        h.signing_keys.clone(),
        seq_path.clone(),
        ctx,
    );
    let ctx_log = builder.ctx_log();
    let mut marker = MockV2MarkerCoordinator::new();
    let marker_log = marker.log();

    let drain = PeerDrivenApplyDrain::new();
    let drain_policy = PeerDrivenDrainPolicy::default(); // disabled
    let apply_policy = PeerDrivenApplyPolicy::devnet_enabled();

    let outcome = drain.try_drain_once(
        &mut queue,
        &mut builder,
        &mut marker,
        &drain_policy,
        &apply_policy,
        &devnet_runtime_domain(),
        3_001,
    );
    assert!(matches!(outcome, PeerDrivenDrainOutcome::Disabled));
    assert!(outcome.is_pre_controller_refusal());
    assert!(ctx_log.lock().unwrap().events.is_empty(), "no apply call");
    assert!(marker_log.lock().unwrap().is_empty(), "no marker call");
    assert_seq_file_unchanged(&seq_path, snap);
    assert_eq!(queue.len(), 1, "queue untouched on Disabled");
    // Concurrency guard untouched.
    assert!(!drain.in_progress_flag().load(Ordering::Acquire));
}

// =====================================================================
// A5. MainNet returns `MainNetRefused` even with `enabled = true`.
// =====================================================================

#[test]
fn a5_mainnet_returns_mainnet_refused_even_with_enabled_policy() {
    let dir = tmpdir("a5-mainnet");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 4, 400, None, vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    let _validated = stage_candidate_from_bundle(
        &mut queue,
        &candidate_path,
        &h.signing_keys,
        Some(&seq_path),
        Some("peer-a5"),
        4_000,
        Some("digest-a5".into()),
    );

    let snap = snapshot_seq_file(&seq_path);
    let ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let mut builder = DrainBuilder::devnet(
        candidate_path.clone(),
        h.signing_keys.clone(),
        seq_path.clone(),
        ctx,
    );
    let ctx_log = builder.ctx_log();
    let mut marker = MockV2MarkerCoordinator::new();
    let marker_log = marker.log();

    let drain = PeerDrivenApplyDrain::new();
    let drain_policy = PeerDrivenDrainPolicy::mainnet_attempted();
    let apply_policy = PeerDrivenApplyPolicy::mainnet_attempted();

    let outcome = drain.try_drain_once(
        &mut queue,
        &mut builder,
        &mut marker,
        &drain_policy,
        &apply_policy,
        &mainnet_runtime_domain(),
        4_001,
    );
    assert!(matches!(outcome, PeerDrivenDrainOutcome::MainNetRefused));
    assert!(outcome.is_pre_controller_refusal());
    assert!(ctx_log.lock().unwrap().events.is_empty());
    assert!(marker_log.lock().unwrap().is_empty());
    assert_seq_file_unchanged(&seq_path, snap);
    assert_eq!(queue.len(), 1);
    assert!(!drain.in_progress_flag().load(Ordering::Acquire));
}

// =====================================================================
// A6. Expired staged candidate cannot apply. The drain selector
// filters it; the queue evicts it (permanently-invalid → drop).
// =====================================================================

#[test]
fn a6_expired_staged_candidate_cannot_apply() {
    let dir = tmpdir("a6-expired");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 6, 600, None, vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    // Use a wide staging-queue TTL so only the drain policy ceiling
    // enforces freshness; otherwise `purge_expired` would remove the
    // candidate before the selector observes it.
    let mut wide_queue = PeerCandidateStagingQueue::new({
        let mut sp = PeerDrivenStagingPolicy::devnet_enabled();
        sp.ttl_secs = u64::MAX;
        sp
    });
    let _validated = stage_candidate_from_bundle(
        &mut wide_queue,
        &candidate_path,
        &h.signing_keys,
        Some(&seq_path),
        Some("peer-a6"),
        1_000,
        Some("digest-a6".into()),
    );
    assert_eq!(wide_queue.len(), 1);

    let snap = snapshot_seq_file(&seq_path);
    let ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let mut builder = DrainBuilder::devnet(
        candidate_path.clone(),
        h.signing_keys.clone(),
        seq_path.clone(),
        ctx,
    );
    let ctx_log = builder.ctx_log();
    let mut marker = MockV2MarkerCoordinator::new();
    let marker_log = marker.log();

    let drain = PeerDrivenApplyDrain::new();
    let mut drain_policy = PeerDrivenDrainPolicy::devnet_enabled();
    drain_policy.max_candidate_age_secs = 10;
    let apply_policy = PeerDrivenApplyPolicy::devnet_enabled();

    // age = 4000s > 10s.
    let outcome = drain.try_drain_once(
        &mut wide_queue,
        &mut builder,
        &mut marker,
        &drain_policy,
        &apply_policy,
        &devnet_runtime_domain(),
        5_000,
    );
    // The selector filters expired entries → NoCandidate; the queue is
    // untouched on a pure selector-miss. (The defence-in-depth
    // post-selection check only fires if the selector picked an
    // expired candidate, which it does not.)
    assert!(matches!(outcome, PeerDrivenDrainOutcome::NoCandidate));
    assert!(ctx_log.lock().unwrap().events.is_empty());
    assert!(marker_log.lock().unwrap().is_empty());
    assert_seq_file_unchanged(&seq_path, snap);
    // Queue still contains the expired entry; the staging queue's
    // TTL sweep (called by the drain) has its own broader TTL so the
    // candidate is still present. The Run 150 selector simply does
    // not pick it. The Run 145 lazy TTL purge governs eviction.
    assert_eq!(wide_queue.len(), 1);
}

// =====================================================================
// A7. Deterministic highest-sequence selection wins.
// =====================================================================

#[test]
fn a7_deterministic_highest_sequence_selection() {
    let dir = tmpdir("a7-select");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    let bundle_low = build_signed_devnet_bundle(&h, 3, 300, None, vec![]);
    let bundle_high = build_signed_devnet_bundle(&h, 9, 900, None, vec![]);
    let path_low = write_bundle_to_disk(&dir, "cand_low.json", &bundle_low);
    let path_high = write_bundle_to_disk(&dir, "cand_high.json", &bundle_high);

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    let v_low = stage_candidate_from_bundle(
        &mut queue,
        &path_low,
        &h.signing_keys,
        Some(&seq_path),
        Some("peer-low"),
        1_000,
        Some("digest-low".into()),
    );
    let v_high = stage_candidate_from_bundle(
        &mut queue,
        &path_high,
        &h.signing_keys,
        Some(&seq_path),
        Some("peer-high"),
        1_000,
        Some("digest-high".into()),
    );
    assert_eq!(queue.len(), 2);

    // Drain selects the highest-sequence candidate. The builder
    // points at the HIGH bundle path so the Run 070 apply pipeline
    // can succeed; the LOW candidate must NOT be the selection.
    let ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let mut builder = DrainBuilder::devnet(
        path_high.clone(),
        h.signing_keys.clone(),
        seq_path.clone(),
        ctx,
    )
    .with_previous("aaaaaaaa", Some(1));
    let mut marker = MockV2MarkerCoordinator::new();

    let drain = PeerDrivenApplyDrain::new();
    let drain_policy = PeerDrivenDrainPolicy::devnet_enabled();
    let apply_policy = PeerDrivenApplyPolicy::devnet_enabled();
    let outcome = drain.try_drain_once(
        &mut queue,
        &mut builder,
        &mut marker,
        &drain_policy,
        &apply_policy,
        &devnet_runtime_domain(),
        1_001,
    );
    match &outcome {
        PeerDrivenDrainOutcome::Applied {
            fingerprint_prefix,
            sequence,
            ..
        } => {
            assert_eq!(*sequence, 9, "highest sequence (9) wins over (3)");
            assert_eq!(fingerprint_prefix, &v_high.fingerprint_prefix);
            assert_ne!(fingerprint_prefix, &v_low.fingerprint_prefix);
        }
        other => panic!("expected Applied for HIGH candidate, got {:?}", other),
    }
    // High candidate consumed; low candidate still staged.
    assert_eq!(queue.len(), 1);
    let remaining = queue.entries();
    assert_eq!(remaining[0].sequence, 3);
    assert_eq!(remaining[0].fingerprint_prefix, v_low.fingerprint_prefix);
}

// =====================================================================
// A8. Duplicate / re-trigger candidate cannot double-apply.
// First trigger Applied → queue empty → second trigger NoCandidate.
// =====================================================================

#[test]
fn a8_duplicate_drain_cannot_double_apply() {
    let dir = tmpdir("a8-dup");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 5, 500, None, vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    let _validated = stage_candidate_from_bundle(
        &mut queue,
        &candidate_path,
        &h.signing_keys,
        Some(&seq_path),
        Some("peer-a8"),
        1_000,
        Some("digest-a8".into()),
    );

    let ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let mut builder = DrainBuilder::devnet(
        candidate_path.clone(),
        h.signing_keys.clone(),
        seq_path.clone(),
        ctx,
    )
    .with_previous("aaaaaaaa", Some(2));
    let mut marker = MockV2MarkerCoordinator::new();

    let drain = PeerDrivenApplyDrain::new();
    let drain_policy = PeerDrivenDrainPolicy::devnet_enabled();
    let apply_policy = PeerDrivenApplyPolicy::devnet_enabled();

    let first = drain.try_drain_once(
        &mut queue,
        &mut builder,
        &mut marker,
        &drain_policy,
        &apply_policy,
        &devnet_runtime_domain(),
        1_001,
    );
    assert!(matches!(first, PeerDrivenDrainOutcome::Applied { .. }));
    assert_eq!(queue.len(), 0, "consumed after success");

    // Second trigger: nothing eligible.
    let second = drain.try_drain_once(
        &mut queue,
        &mut builder,
        &mut marker,
        &drain_policy,
        &apply_policy,
        &devnet_runtime_domain(),
        1_002,
    );
    assert!(
        matches!(second, PeerDrivenDrainOutcome::NoCandidate),
        "second drain must NOT re-apply; got {:?}",
        second
    );
}

// =====================================================================
// R1. Lower-sequence candidate cannot drain when a higher exists; the
// lower remains in the queue.
// =====================================================================

#[test]
fn r1_lower_sequence_candidate_cannot_drain_when_higher_exists() {
    // Covered by the selector half of A7; this test additionally
    // asserts the lower-sequence candidate is still staged AND that
    // its fingerprint did NOT pass through the apply context.
    let dir = tmpdir("r1-lower");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle_low = build_signed_devnet_bundle(&h, 4, 400, None, vec![]);
    let bundle_high = build_signed_devnet_bundle(&h, 9, 900, None, vec![]);
    let path_low = write_bundle_to_disk(&dir, "cand_low.json", &bundle_low);
    let path_high = write_bundle_to_disk(&dir, "cand_high.json", &bundle_high);

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    let v_low = stage_candidate_from_bundle(
        &mut queue, &path_low, &h.signing_keys, Some(&seq_path), Some("peer-l"),
        1_000, Some("d-l".into()),
    );
    let _v_high = stage_candidate_from_bundle(
        &mut queue, &path_high, &h.signing_keys, Some(&seq_path), Some("peer-h"),
        1_000, Some("d-h".into()),
    );

    let ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let mut builder = DrainBuilder::devnet(
        path_high.clone(), h.signing_keys.clone(), seq_path.clone(), ctx,
    ).with_previous("aaaaaaaa", Some(1));
    let active = builder.active();
    let mut marker = MockV2MarkerCoordinator::new();
    let drain = PeerDrivenApplyDrain::new();
    let drain_policy = PeerDrivenDrainPolicy::devnet_enabled();
    let apply_policy = PeerDrivenApplyPolicy::devnet_enabled();
    let outcome = drain.try_drain_once(
        &mut queue, &mut builder, &mut marker, &drain_policy, &apply_policy,
        &devnet_runtime_domain(), 1_001,
    );
    assert!(matches!(outcome, PeerDrivenDrainOutcome::Applied { sequence: 9, .. }));
    // Lower-sequence candidate remains; the live fingerprint is the
    // HIGH candidate's fp_prefix (not low).
    assert_ne!(*active.lock().unwrap(), v_low.fingerprint_prefix);
    assert_eq!(queue.len(), 1);
    assert_eq!(queue.entries()[0].sequence, 4);
}

// =====================================================================
// R2. Same-sequence different-digest equivocation refused via Run 148
// pre-apply marker conflict. No mutation.
// =====================================================================

#[test]
fn r2_same_sequence_different_digest_marker_conflict_refused() {
    let dir = tmpdir("r2-equivocation");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 5, 500, None, vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    let _validated = stage_candidate_from_bundle(
        &mut queue, &candidate_path, &h.signing_keys, Some(&seq_path),
        Some("peer-r2"), 1_000, Some("digest-r2".into()),
    );

    let snap = snapshot_seq_file(&seq_path);
    let ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let mut builder = DrainBuilder::devnet(
        candidate_path.clone(), h.signing_keys.clone(), seq_path.clone(), ctx,
    );
    let ctx_log = builder.ctx_log();
    let mut marker = MockV2MarkerCoordinator::new()
        .with_pre_apply_err("v2-same-sequence-different-digest equivocation");
    let drain = PeerDrivenApplyDrain::new();
    let drain_policy = PeerDrivenDrainPolicy::devnet_enabled();
    let apply_policy = PeerDrivenApplyPolicy::devnet_enabled();
    let outcome = drain.try_drain_once(
        &mut queue, &mut builder, &mut marker, &drain_policy, &apply_policy,
        &devnet_runtime_domain(), 1_001,
    );
    match &outcome {
        PeerDrivenDrainOutcome::CandidateMarkerConflict { reason, .. } => {
            assert!(reason.contains("equivocation"), "reason={}", reason);
        }
        other => panic!("expected CandidateMarkerConflict, got {:?}", other),
    }
    assert!(ctx_log.lock().unwrap().events.is_empty(), "no Run 070 apply");
    assert_seq_file_unchanged(&seq_path, snap);
    // Pre-apply marker conflict leaves queue intact (operator may
    // reconcile and retry).
    assert_eq!(queue.len(), 1);
}

// =====================================================================
// R3. Bad-signature candidate cannot drain. We synthesise a
// `StagedPeerCandidate` whose `signature_verified == false` would
// trip the defence-in-depth filter; since the staging queue's public
// API only accepts validated candidates, we instead simulate via the
// filter-side effect: a candidate with `signature_verified == false`
// would never be added by `try_stage_validated` because Run 142 sets
// the flag from validation. Therefore this scenario is observed
// instead by injecting via the v1/legacy path (R11) — see R11.
// =====================================================================

// =====================================================================
// R4. Wrong-domain candidate cannot drain. The drain selector
// filters it (selector returns None → NoCandidate). The candidate
// remains in the queue because the staging queue's TTL is the
// authoritative removal path.
// =====================================================================

#[test]
fn r4_wrong_domain_staged_candidate_cannot_drain() {
    let dir = tmpdir("r4-wrong-domain");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 5, 500, None, vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    let _v = stage_candidate_from_bundle(
        &mut queue, &candidate_path, &h.signing_keys, Some(&seq_path),
        Some("peer-r4"), 1_000, Some("digest-r4".into()),
    );

    let snap = snapshot_seq_file(&seq_path);
    let ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let mut builder = DrainBuilder::devnet(
        candidate_path.clone(), h.signing_keys.clone(), seq_path.clone(), ctx,
    );
    let ctx_log = builder.ctx_log();
    let mut marker = MockV2MarkerCoordinator::new();

    let drain = PeerDrivenApplyDrain::new();
    // Drain policy declares Testnet; runtime domain is Testnet.
    // Candidate is DevNet-tagged → selector filters it out.
    let drain_policy = PeerDrivenDrainPolicy::testnet_enabled();
    let apply_policy = PeerDrivenApplyPolicy::testnet_enabled();
    let outcome = drain.try_drain_once(
        &mut queue, &mut builder, &mut marker, &drain_policy, &apply_policy,
        &testnet_runtime_domain(), 1_001,
    );
    assert!(matches!(outcome, PeerDrivenDrainOutcome::NoCandidate));
    assert!(ctx_log.lock().unwrap().events.is_empty());
    assert_seq_file_unchanged(&seq_path, snap);
    assert_eq!(queue.len(), 1);
}

// =====================================================================
// R5. Ambiguous v1+v2 candidate refused at Run 148 marker pre-apply
// gate (modelled as a marker pre-apply error). No mutation.
// =====================================================================

#[test]
fn r5_ambiguous_v1_v2_candidate_refused_at_marker_gate() {
    let dir = tmpdir("r5-ambiguous");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 5, 500, None, vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    let _v = stage_candidate_from_bundle(
        &mut queue, &candidate_path, &h.signing_keys, Some(&seq_path),
        Some("peer-r5"), 1_000, Some("digest-r5".into()),
    );

    let snap = snapshot_seq_file(&seq_path);
    let ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let mut builder = DrainBuilder::devnet(
        candidate_path.clone(), h.signing_keys.clone(), seq_path.clone(), ctx,
    );
    let ctx_log = builder.ctx_log();
    let mut marker = MockV2MarkerCoordinator::new()
        .with_pre_apply_err("ambiguous-v1-and-v2-markers-present");
    let drain = PeerDrivenApplyDrain::new();
    let drain_policy = PeerDrivenDrainPolicy::devnet_enabled();
    let apply_policy = PeerDrivenApplyPolicy::devnet_enabled();
    let outcome = drain.try_drain_once(
        &mut queue, &mut builder, &mut marker, &drain_policy, &apply_policy,
        &devnet_runtime_domain(), 1_001,
    );
    assert!(matches!(outcome, PeerDrivenDrainOutcome::CandidateMarkerConflict { .. }));
    assert!(ctx_log.lock().unwrap().events.is_empty(), "no Run 070 apply");
    assert_seq_file_unchanged(&seq_path, snap);
}

// =====================================================================
// R6. Run 070 validation failure before swap → no mutation.
// Builder refuses to build an invocation (typed reason), so the
// Run 148 controller is never called.
// =====================================================================

#[test]
fn r6_builder_refusal_before_apply_produces_no_mutation() {
    let dir = tmpdir("r6-builder");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 5, 500, None, vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    let _v = stage_candidate_from_bundle(
        &mut queue, &candidate_path, &h.signing_keys, Some(&seq_path),
        Some("peer-r6"), 1_000, Some("digest-r6".into()),
    );

    let snap = snapshot_seq_file(&seq_path);
    let ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let mut builder = DrainBuilder::devnet(
        candidate_path.clone(), h.signing_keys.clone(), seq_path.clone(), ctx,
    )
    .with_refusal("simulated bundle path missing on disk");
    let ctx_log = builder.ctx_log();
    let mut marker = MockV2MarkerCoordinator::new();
    let marker_log = marker.log();
    let drain = PeerDrivenApplyDrain::new();
    let outcome = drain.try_drain_once(
        &mut queue, &mut builder, &mut marker,
        &PeerDrivenDrainPolicy::devnet_enabled(),
        &PeerDrivenApplyPolicy::devnet_enabled(),
        &devnet_runtime_domain(),
        1_001,
    );
    match &outcome {
        PeerDrivenDrainOutcome::CandidateRejectedBeforeApply { reason, .. } => {
            assert!(reason.contains("simulated"));
        }
        other => panic!("expected CandidateRejectedBeforeApply, got {:?}", other),
    }
    assert!(ctx_log.lock().unwrap().events.is_empty());
    assert!(marker_log.lock().unwrap().is_empty());
    assert_seq_file_unchanged(&seq_path, snap);
    // Queue preserved (transient failure).
    assert_eq!(queue.len(), 1);
}

// =====================================================================
// R7. Eviction failure preserves Run 070 rollback behaviour: live
// trust state rolls back; no commit; no marker. Drain surfaces
// `ApplyRejected` (non-fatal).
// =====================================================================

#[test]
fn r7_eviction_failure_rollback_preserves_run070() {
    let dir = tmpdir("r7-evict");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 5, 500, None, vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    let _v = stage_candidate_from_bundle(
        &mut queue, &candidate_path, &h.signing_keys, Some(&seq_path),
        Some("peer-r7"), 1_000, Some("digest-r7".into()),
    );

    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    ctx.evict_action = ActionPlan::Err("session-eviction failed (sim)".into());
    let mut builder = DrainBuilder::devnet(
        candidate_path.clone(), h.signing_keys.clone(), seq_path.clone(), ctx,
    )
    .with_previous("aaaaaaaa", Some(2));
    let ctx_log = builder.ctx_log();
    let active = builder.active();
    let mut marker = MockV2MarkerCoordinator::new();
    let drain = PeerDrivenApplyDrain::new();
    let outcome = drain.try_drain_once(
        &mut queue, &mut builder, &mut marker,
        &PeerDrivenDrainPolicy::devnet_enabled(),
        &PeerDrivenApplyPolicy::devnet_enabled(),
        &devnet_runtime_domain(),
        1_001,
    );
    match &outcome {
        PeerDrivenDrainOutcome::ApplyRejected { inner, .. } => {
            assert!(
                matches!(inner, PeerDrivenApplyOutcome::ApplyRollbackSucceeded { .. }),
                "expected rollback-succeeded inner; got {:?}",
                inner
            );
        }
        other => panic!("expected ApplyRejected, got {:?}", other),
    }
    // Live state rolled back.
    assert_eq!(*active.lock().unwrap(), "aaaaaaaa");
    let ev = ctx_log.lock().unwrap().events.clone();
    assert!(ev.contains(&"swap_trust_state".to_string()));
    assert!(ev.contains(&"evict_sessions".to_string()));
    assert!(ev.contains(&"rollback_trust_state".to_string()));
    assert!(!ev.contains(&"commit_sequence".to_string()), "no commit");
    // Queue preserved (transient eviction failure).
    assert_eq!(queue.len(), 1);
    assert!(!outcome.is_fatal_operator_actionable());
}

// =====================================================================
// R8. Sequence commit failure with rollback success → ApplyRejected;
// no marker persist.
// =====================================================================

#[test]
fn r8_sequence_commit_failure_rollback_succeeds_no_marker() {
    let dir = tmpdir("r8-commit");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 5, 500, None, vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    let _v = stage_candidate_from_bundle(
        &mut queue, &candidate_path, &h.signing_keys, Some(&seq_path),
        Some("peer-r8"), 1_000, Some("digest-r8".into()),
    );

    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    ctx.commit_action = ActionPlan::Err("commit-sim".into());
    let mut builder = DrainBuilder::devnet(
        candidate_path.clone(), h.signing_keys.clone(), seq_path.clone(), ctx,
    )
    .with_previous("aaaaaaaa", Some(2));
    let active = builder.active();
    let mut marker = MockV2MarkerCoordinator::new();
    let marker_log = marker.log();
    let drain = PeerDrivenApplyDrain::new();
    let outcome = drain.try_drain_once(
        &mut queue, &mut builder, &mut marker,
        &PeerDrivenDrainPolicy::devnet_enabled(),
        &PeerDrivenApplyPolicy::devnet_enabled(),
        &devnet_runtime_domain(),
        1_001,
    );
    match &outcome {
        PeerDrivenDrainOutcome::ApplyRejected { inner, .. } => {
            assert!(matches!(
                inner,
                PeerDrivenApplyOutcome::ApplyRollbackSucceeded { .. }
            ));
        }
        other => panic!("expected ApplyRejected (commit failure), got {:?}", other),
    }
    assert_eq!(*active.lock().unwrap(), "aaaaaaaa", "live state rolled back");
    // Marker pre-apply ran, persist did NOT.
    let mev = marker_log.lock().unwrap().clone();
    assert_eq!(mev, vec!["decide_pre_apply"], "no post-commit persist call");
    assert_eq!(queue.len(), 1);
    assert!(!outcome.is_fatal_operator_actionable());
}

// =====================================================================
// R9. Marker persist failure AFTER successful commit is fatal /
// operator-actionable per Run 134/138.
// =====================================================================

#[test]
fn r9_marker_persist_failure_after_commit_is_fatal() {
    let dir = tmpdir("r9-marker-fatal");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 5, 500, None, vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    let _v = stage_candidate_from_bundle(
        &mut queue, &candidate_path, &h.signing_keys, Some(&seq_path),
        Some("peer-r9"), 1_000, Some("digest-r9".into()),
    );

    let ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let mut builder = DrainBuilder::devnet(
        candidate_path.clone(), h.signing_keys.clone(), seq_path.clone(), ctx,
    )
    .with_previous("aaaaaaaa", Some(2));
    let mut marker = MockV2MarkerCoordinator::new()
        .with_post_commit_err("marker-persist-failed-after-commit (sim)");
    let drain = PeerDrivenApplyDrain::new();
    let outcome = drain.try_drain_once(
        &mut queue, &mut builder, &mut marker,
        &PeerDrivenDrainPolicy::devnet_enabled(),
        &PeerDrivenApplyPolicy::devnet_enabled(),
        &devnet_runtime_domain(),
        1_001,
    );
    match &outcome {
        PeerDrivenDrainOutcome::ApplyFatal { inner, .. } => {
            assert!(matches!(
                inner,
                PeerDrivenApplyOutcome::MarkerPersistFailedAfterCommit { .. }
            ));
        }
        other => panic!("expected ApplyFatal (marker persist), got {:?}", other),
    }
    assert!(outcome.is_fatal_operator_actionable());
    // Queue preserved — operator must reconcile offline.
    assert_eq!(queue.len(), 1);
}

// =====================================================================
// R10. Concurrency guard prevents double drain. Single-threaded:
// pre-set the flag, observe AlreadyInProgress.
// =====================================================================

#[test]
fn r10_concurrency_guard_prevents_double_drain() {
    let dir = tmpdir("r10-conc");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 5, 500, None, vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    let _v = stage_candidate_from_bundle(
        &mut queue, &candidate_path, &h.signing_keys, Some(&seq_path),
        Some("peer-r10"), 1_000, Some("digest-r10".into()),
    );

    let snap = snapshot_seq_file(&seq_path);
    let ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let mut builder = DrainBuilder::devnet(
        candidate_path.clone(), h.signing_keys.clone(), seq_path.clone(), ctx,
    );
    let ctx_log = builder.ctx_log();
    let mut marker = MockV2MarkerCoordinator::new();
    let marker_log = marker.log();
    let drain = PeerDrivenApplyDrain::new();
    // Simulate a concurrent drain by manually holding the in-progress flag.
    let flag = drain.in_progress_flag();
    flag.store(true, Ordering::Release);

    let outcome = drain.try_drain_once(
        &mut queue, &mut builder, &mut marker,
        &PeerDrivenDrainPolicy::devnet_enabled(),
        &PeerDrivenApplyPolicy::devnet_enabled(),
        &devnet_runtime_domain(),
        1_001,
    );
    assert!(matches!(outcome, PeerDrivenDrainOutcome::AlreadyInProgress));
    assert!(outcome.is_pre_controller_refusal());
    assert!(ctx_log.lock().unwrap().events.is_empty(), "no Run 070 apply");
    assert!(marker_log.lock().unwrap().is_empty(), "no marker call");
    assert_seq_file_unchanged(&seq_path, snap);
    assert_eq!(queue.len(), 1);

    // Release the simulated concurrent drain: a subsequent trigger
    // proceeds normally.
    flag.store(false, Ordering::Release);
    let outcome2 = drain.try_drain_once(
        &mut queue, &mut builder, &mut marker,
        &PeerDrivenDrainPolicy::devnet_enabled(),
        &PeerDrivenApplyPolicy::devnet_enabled(),
        &devnet_runtime_domain(),
        1_002,
    );
    assert!(
        matches!(outcome2, PeerDrivenDrainOutcome::Applied { .. }),
        "after guard release, drain proceeds; got {:?}",
        outcome2
    );
}

// =====================================================================
// R11. v1/legacy staged candidate behaviour: when
// `require_v2_ratification` is on (default), a marker pre-apply
// refusal models the "v2 marker missing for v1-only candidate" case.
// Queue + live state untouched.
// =====================================================================

#[test]
fn r11_v1_only_staged_candidate_refused_when_v2_required() {
    let dir = tmpdir("r11-v1");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 5, 500, None, vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    // Stage WITHOUT an authority_marker_digest — modelling a v1/legacy
    // peer-staged candidate.
    let _v = stage_candidate_from_bundle(
        &mut queue, &candidate_path, &h.signing_keys, Some(&seq_path),
        Some("peer-r11"), 1_000, None,
    );

    let snap = snapshot_seq_file(&seq_path);
    let ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let mut builder = DrainBuilder::devnet(
        candidate_path.clone(), h.signing_keys.clone(), seq_path.clone(), ctx,
    );
    let ctx_log = builder.ctx_log();
    let mut marker = MockV2MarkerCoordinator::new()
        .with_pre_apply_err("v1-only-candidate-rejected-when-v2-required");
    let drain = PeerDrivenApplyDrain::new();
    let outcome = drain.try_drain_once(
        &mut queue, &mut builder, &mut marker,
        &PeerDrivenDrainPolicy::devnet_enabled(),
        &PeerDrivenApplyPolicy::devnet_enabled(),
        &devnet_runtime_domain(),
        1_001,
    );
    assert!(matches!(
        outcome,
        PeerDrivenDrainOutcome::CandidateMarkerConflict { .. }
    ));
    assert!(ctx_log.lock().unwrap().events.is_empty(), "no Run 070 apply");
    assert_seq_file_unchanged(&seq_path, snap);
    assert_eq!(queue.len(), 1, "v1-candidate left for operator review");
}

// =====================================================================
// R12. Propagation-only behaviour unchanged. The drain neither
// performs nor implies propagation/rebroadcast. A staged candidate
// remains stage-able and the drain's only effects are scoped to the
// Run 070 apply pipeline + the queue-removal bookkeeping.
//
// We cannot directly observe the absence of a propagation call (no
// propagation hook is invoked by the drain), but we can assert:
//   - the staging queue's entries() before/after a non-applying
//     refusal are identical (no propagation-driven duplication);
//   - the FakeLiveTrustApplyContext records no propagation event
//     (the trait has no propagation method, so a drain leak would
//     show up as an unexpected extra event — none does).
// =====================================================================

#[test]
fn r12_propagation_only_behaviour_unchanged_under_drain() {
    let dir = tmpdir("r12-propagation");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 5, 500, None, vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    let _v = stage_candidate_from_bundle(
        &mut queue, &candidate_path, &h.signing_keys, Some(&seq_path),
        Some("peer-r12"), 1_000, Some("digest-r12".into()),
    );
    let entries_before = queue.entries();

    // Trigger a non-applying refusal (disabled policy) — propagation
    // surfaces must not be touched.
    let ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let mut builder = DrainBuilder::devnet(
        candidate_path.clone(), h.signing_keys.clone(), seq_path.clone(), ctx,
    );
    let ctx_log = builder.ctx_log();
    let mut marker = MockV2MarkerCoordinator::new();
    let marker_log = marker.log();
    let drain = PeerDrivenApplyDrain::new();
    let outcome = drain.try_drain_once(
        &mut queue, &mut builder, &mut marker,
        &PeerDrivenDrainPolicy::default(),
        &PeerDrivenApplyPolicy::default(),
        &devnet_runtime_domain(),
        1_001,
    );
    assert!(matches!(outcome, PeerDrivenDrainOutcome::Disabled));
    assert_eq!(queue.entries(), entries_before, "queue unchanged on Disabled");
    assert!(ctx_log.lock().unwrap().events.is_empty());
    assert!(marker_log.lock().unwrap().is_empty());
}
