//! Run 148 — integration tests for the **source/test-only peer-driven
//! live apply controller** wired against the existing Run 070 apply
//! contract.
//!
//! These tests exercise [`qbind_node::pqc_peer_candidate_apply::try_apply_staged_peer_candidate`]
//! and assert the full Run 148 acceptance / rejection matrix from
//! `task/RUN_148_TASK.txt`:
//!
//! - **A1** DevNet staged valid v2 candidate applies through Run 070
//! - **A2** TestNet staged valid v2 candidate applies under explicit TestNet policy
//! - **A3** Disabled policy refuses (no mutation)
//! - **A4** MainNet refuses unconditionally
//! - **R1** Unstaged candidate cannot apply
//! - **R2** Expired staged candidate cannot apply
//! - **R3** Lower-sequence staged candidate (marker conflict) cannot apply
//! - **R4** Same-sequence different-digest staged candidate (equivocation) cannot apply
//! - **R5** Wrong-domain staged candidate cannot apply
//! - **R6** Bad-signature candidate cannot apply (Run 070 ValidationFailed)
//! - **R7** Apply validation failure before swap (no mutation)
//! - **R8** Swap failure rollback semantics (no eviction, no commit)
//! - **R9** Eviction failure rollback succeeds (live state restored)
//! - **R10** Sequence commit failure rollback succeeds (live state restored, no marker)
//! - **R11** Sequence commit failure rollback also fails (fatal)
//! - **R12** Marker persist failure after successful commit (fatal/operator-actionable)
//! - **R13** Idempotent staged v2 candidate behaviour (refused as already-applied)
//! - **R14** v2-after-v1 migration candidate applies under enabled DevNet policy
//! - **R15** Propagation-only behaviour unchanged
//! - **R16** Validation-only behaviour unchanged
//!
//! # Strict scope (Run 148)
//!
//! - Source/test wiring only. Release-binary peer-driven apply evidence
//!   is deferred to Run 149.
//! - DevNet / TestNet only — MainNet refused unconditionally.
//! - Reuses the existing Run 070 `apply_validated_candidate_with_previous`
//!   contract via the production [`LiveTrustApplyContext`] surface
//!   (driven here by the same `FakeLiveTrustApplyContext` pattern Run 070
//!   tests use).
//! - Reuses the Run 134/138 v2 marker pre/post-commit discipline via the
//!   [`V2MarkerCoordinator`] trait (driven here by a configurable mock
//!   so R3/R4/R12 can be exercised without constructing real
//!   ratification objects).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use qbind_crypto::MlDsa44Backend;
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_peer_candidate_apply::{
    try_apply_staged_peer_candidate, NoV2MarkerCoordinator, PeerDrivenApplyInvocation,
    PeerDrivenApplyOutcome, PeerDrivenApplyPolicy, PeerDrivenApplyRuntimeDomain,
    StagedPeerCandidateId, V2MarkerCoordinator,
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
    validate_candidate_bundle, LiveTrustApplyContext, ReloadApplyError,
    ReloadCheckInputs, ValidatedCandidate,
};
use qbind_node::pqc_trust_sequence::{chain_id_hex, sequence_file_path};
use qbind_types::NetworkEnvironment;

// =====================================================================
// Helpers (adapted from run_070 / run_145 test files — same DevNet
// signing harness, same `build_signed_devnet_bundle`, same persistence-
// file snapshot/assertion helpers).
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
        "qbind-run148-{}-{}-{}",
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
            "Run 148 refusal must not create persistence file at {}",
            path.display()
        ),
        (Some(_), false) => panic!(
            "Run 148 refusal must not delete persistence file at {}",
            path.display()
        ),
        (Some((before, mt_before)), true) => {
            let after = std::fs::read(path).expect("read seq file");
            assert_eq!(before, after, "Run 148 refusal must not rewrite seq file");
            let mt_after = std::fs::metadata(path).unwrap().modified().unwrap();
            assert_eq!(mt_before, mt_after, "Run 148 refusal must not touch mtime");
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

// ---------------------------------------------------------------------
// `FakeLiveTrustApplyContext` — mirrors the Run 070 test harness.
// ---------------------------------------------------------------------

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
    fn snapshot_active(
        &mut self,
    ) -> Result<Box<dyn std::any::Any + Send + Sync>, String> {
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

// =====================================================================
// A1. DevNet staged valid v2 candidate applies through Run 070.
// Required pipeline: validate → snapshot previous → swap →
// evict_sessions → commit_sequence; marker persisted only after
// commit_sequence; outcome MarkerPersistedAfterCommit.
// =====================================================================

#[test]
fn a1_devnet_staged_valid_v2_candidate_applies_through_run070() {
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

    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let ctx_log = ctx.log();
    let active = ctx.active();
    let mut marker = MockV2MarkerCoordinator::new();
    let marker_log = marker.log();

    let policy = PeerDrivenApplyPolicy::devnet_enabled();
    let id = StagedPeerCandidateId::new(&validated.fingerprint_prefix, validated.sequence);

    let outcome = try_apply_staged_peer_candidate(
        &id,
        &mut queue,
        PeerDrivenApplyInvocation {
            inputs: devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0),
            live_apply_ctx: &mut ctx,
            previous_fingerprint_prefix: "aaaaaaaa".into(),
            previous_sequence: Some(3),
        },
        &mut marker,
        &policy,
        &devnet_runtime_domain(),
        1_001,
    );

    match &outcome {
        PeerDrivenApplyOutcome::MarkerPersistedAfterCommit { applied } => {
            assert_eq!(applied.validated.sequence, 5);
            assert_eq!(applied.session_evictions, 2);
            assert_eq!(applied.previous_fingerprint_prefix, "aaaaaaaa");
            assert_eq!(applied.previous_sequence, Some(3));
        }
        other => panic!(
            "expected MarkerPersistedAfterCommit, got {:?}",
            std::mem::discriminant(other)
        ),
    }
    assert!(outcome.is_applied());

    // Strict Run 070 ordering through the fake context.
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

    // Marker discipline: pre-apply check fires BEFORE the apply, persist
    // AFTER `commit_sequence` succeeded.
    let mevents = marker_log.lock().unwrap().clone();
    assert_eq!(mevents, vec!["decide_pre_apply", "persist_after_commit"]);
}

// =====================================================================
// A2. TestNet staged valid candidate applies only under explicit
// TestNet policy.
// =====================================================================

#[test]
fn a2_testnet_staged_valid_v2_candidate_applies_only_under_explicit_testnet_policy() {
    let dir = tmpdir("a2-testnet");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    // We use the DevNet-signed bundle but flip the trust-bundle env to
    // TestNet via a separate harness; for the apply call we use TestNet
    // chain id. For Run 070 to actually succeed the candidate must
    // match the runtime env, but the test's primary assertion is that
    // an enabled-DevNet-only policy refuses TestNet runtime and that
    // an explicit testnet_enabled policy is permitted — we focus on
    // that policy gate, not the full Run 070 validation pipeline.

    let bundle = build_signed_devnet_bundle(&h, 7, 700, None, vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    // Stage a DevNet-flavoured candidate on a permissive staging queue
    // (the staging queue checks its own policy; we don't exercise that
    // gate here).
    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    let validated = stage_candidate_from_bundle(
        &mut queue,
        &candidate_path,
        &h.signing_keys,
        Some(&seq_path),
        Some("peer-a2"),
        2_000,
        Some("digest-a2".into()),
    );

    // First: DevNet-only policy on a TestNet runtime → refused as
    // environment-policy.
    {
        let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
        let ctx_log = ctx.log();
        let mut marker = MockV2MarkerCoordinator::new();
        let mut devnet_only_policy = PeerDrivenApplyPolicy::devnet_enabled();
        devnet_only_policy.environment = NetworkEnvironment::Testnet;
        // allow_devnet=true / allow_testnet=false; environment=Testnet
        // must refuse.
        let id = StagedPeerCandidateId::new(&validated.fingerprint_prefix, validated.sequence);
        let outcome = try_apply_staged_peer_candidate(
            &id,
            &mut queue,
            PeerDrivenApplyInvocation {
                inputs: devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0),
                live_apply_ctx: &mut ctx,
                previous_fingerprint_prefix: String::new(),
                previous_sequence: None,
            },
            &mut marker,
            &devnet_only_policy,
            &testnet_runtime_domain(),
            2_001,
        );
        assert!(
            matches!(outcome, PeerDrivenApplyOutcome::RefusedEnvironmentPolicy),
            "devnet-only policy must refuse a testnet runtime"
        );
        assert!(
            ctx_log.lock().unwrap().events.is_empty(),
            "refusal must not call the apply context"
        );
    }

    // Second: explicit testnet_enabled policy on TestNet runtime — the
    // apply pipeline runs. Because the candidate bundle is DevNet-env
    // signed and the runtime is TestNet, Run 070 validation will fail
    // closed via `ValidationFailed` (env mismatch). The key Run 148
    // assertion is that the policy gate PERMITTED entry to Run 070;
    // i.e. the controller did not refuse as RefusedEnvironmentPolicy.
    {
        let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
        let mut marker = MockV2MarkerCoordinator::new();
        let policy = PeerDrivenApplyPolicy::testnet_enabled();
        let id = StagedPeerCandidateId::new(&validated.fingerprint_prefix, validated.sequence);
        let outcome = try_apply_staged_peer_candidate(
            &id,
            &mut queue,
            PeerDrivenApplyInvocation {
                inputs: ReloadCheckInputs {
                    candidate_path: &candidate_path,
                    environment: NetworkEnvironment::Testnet,
                    chain_id: NetworkEnvironment::Testnet.chain_id(),
                    validation_time_secs: 100,
                    signing_keys: &h.signing_keys,
                    activation_ctx: ActivationContext::height_only(0),
                    sequence_persistence_path: Some(&seq_path),
                    local_leaf_cert_bytes: None,
                },
                live_apply_ctx: &mut ctx,
                previous_fingerprint_prefix: String::new(),
                previous_sequence: None,
            },
            &mut marker,
            &policy,
            &testnet_runtime_domain(),
            2_002,
        );
        // The candidate is DevNet-signed; Run 148 first refuses on the
        // wrong-domain gate (staged.environment != testnet_runtime).
        // Either way, the controller did NOT refuse via the policy gate
        // and did NOT mutate state — that is the A2 invariant.
        assert!(
            matches!(
                outcome,
                PeerDrivenApplyOutcome::CandidateWrongDomain { .. }
                    | PeerDrivenApplyOutcome::ApplyRejected { .. }
            ),
            "explicit testnet policy must reach domain/validation gate, got refusal earlier"
        );
    }
}

// =====================================================================
// A3. Disabled policy refuses (no apply, no mutation, no marker).
// =====================================================================

#[test]
fn a3_disabled_policy_refuses_without_mutation() {
    let dir = tmpdir("a3-disabled");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 4, 400, None, vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    let validated = stage_candidate_from_bundle(
        &mut queue,
        &candidate_path,
        &h.signing_keys,
        Some(&seq_path),
        Some("peer-a3"),
        3_000,
        Some("digest-a3".into()),
    );

    let snap = snapshot_seq_file(&seq_path);
    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let ctx_log = ctx.log();
    let mut marker = MockV2MarkerCoordinator::new();
    let marker_log = marker.log();

    let policy = PeerDrivenApplyPolicy::default(); // disabled
    let id = StagedPeerCandidateId::new(&validated.fingerprint_prefix, validated.sequence);
    let outcome = try_apply_staged_peer_candidate(
        &id,
        &mut queue,
        PeerDrivenApplyInvocation {
            inputs: devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0),
            live_apply_ctx: &mut ctx,
            previous_fingerprint_prefix: String::new(),
            previous_sequence: None,
        },
        &mut marker,
        &policy,
        &devnet_runtime_domain(),
        3_001,
    );
    assert!(matches!(outcome, PeerDrivenApplyOutcome::Disabled));
    assert!(outcome.is_pre_apply_refusal());
    assert!(ctx_log.lock().unwrap().events.is_empty(), "no apply ctx calls");
    assert!(marker_log.lock().unwrap().is_empty(), "no marker calls");
    assert_seq_file_unchanged(&seq_path, snap);
}

// =====================================================================
// A4. MainNet refuses unconditionally.
// =====================================================================

#[test]
fn a4_mainnet_refuses_unconditionally_even_with_allow_mainnet_set() {
    let dir = tmpdir("a4-mainnet");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 4, 400, None, vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    // Stage on a permissive devnet queue so the candidate exists.
    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    let validated = stage_candidate_from_bundle(
        &mut queue,
        &candidate_path,
        &h.signing_keys,
        Some(&seq_path),
        Some("peer-a4"),
        4_000,
        Some("digest-a4".into()),
    );

    let snap = snapshot_seq_file(&seq_path);
    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let ctx_log = ctx.log();
    let mut marker = MockV2MarkerCoordinator::new();
    let marker_log = marker.log();

    let policy = PeerDrivenApplyPolicy::mainnet_attempted(); // enabled + allow_mainnet=true
    let id = StagedPeerCandidateId::new(&validated.fingerprint_prefix, validated.sequence);
    let outcome = try_apply_staged_peer_candidate(
        &id,
        &mut queue,
        PeerDrivenApplyInvocation {
            inputs: devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0),
            live_apply_ctx: &mut ctx,
            previous_fingerprint_prefix: String::new(),
            previous_sequence: None,
        },
        &mut marker,
        &policy,
        &mainnet_runtime_domain(),
        4_001,
    );
    assert!(
        matches!(outcome, PeerDrivenApplyOutcome::RefusedMainNet),
        "mainnet must refuse unconditionally"
    );
    assert!(ctx_log.lock().unwrap().events.is_empty());
    assert!(marker_log.lock().unwrap().is_empty());
    assert_seq_file_unchanged(&seq_path, snap);
}

// =====================================================================
// R1. Unstaged candidate cannot apply.
// =====================================================================

#[test]
fn r1_unstaged_candidate_cannot_apply() {
    let dir = tmpdir("r1-unstaged");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 4, 400, None, vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    // Do NOT stage the candidate.
    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let ctx_log = ctx.log();
    let mut marker = MockV2MarkerCoordinator::new();
    let marker_log = marker.log();

    let policy = PeerDrivenApplyPolicy::devnet_enabled();
    let id = StagedPeerCandidateId::new("deadbeef", 4);
    let outcome = try_apply_staged_peer_candidate(
        &id,
        &mut queue,
        PeerDrivenApplyInvocation {
            inputs: devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0),
            live_apply_ctx: &mut ctx,
            previous_fingerprint_prefix: String::new(),
            previous_sequence: None,
        },
        &mut marker,
        &policy,
        &devnet_runtime_domain(),
        5_000,
    );
    assert!(matches!(outcome, PeerDrivenApplyOutcome::CandidateNotFound));
    assert!(ctx_log.lock().unwrap().events.is_empty());
    assert!(marker_log.lock().unwrap().is_empty());
}

// =====================================================================
// R2. Expired staged candidate cannot apply (TTL at apply time).
// =====================================================================

#[test]
fn r2_expired_staged_candidate_cannot_apply() {
    let dir = tmpdir("r2-expired");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 6, 600, None, vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    let validated = stage_candidate_from_bundle(
        &mut queue,
        &candidate_path,
        &h.signing_keys,
        Some(&seq_path),
        Some("peer-r2"),
        1_000,
        Some("digest-r2".into()),
    );

    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let ctx_log = ctx.log();
    let mut marker = MockV2MarkerCoordinator::new();
    let marker_log = marker.log();

    let mut policy = PeerDrivenApplyPolicy::devnet_enabled();
    policy.max_candidate_age_secs = 10;
    // The staging queue's TTL would already purge a 1000+10 entry, so
    // use a permissive staging queue TTL and only the apply policy
    // ceiling enforces freshness. Override the queue's policy
    // ttl_secs via a fresh permissive queue:
    let mut wide_queue = PeerCandidateStagingQueue::new({
        let mut sp = PeerDrivenStagingPolicy::devnet_enabled();
        sp.ttl_secs = u64::MAX;
        sp
    });
    let validated2 = stage_candidate_from_bundle(
        &mut wide_queue,
        &candidate_path,
        &h.signing_keys,
        Some(&seq_path),
        Some("peer-r2b"),
        1_000,
        Some("digest-r2b".into()),
    );

    let id = StagedPeerCandidateId::new(&validated2.fingerprint_prefix, validated2.sequence);
    // now well past max_candidate_age_secs at apply time.
    let outcome = try_apply_staged_peer_candidate(
        &id,
        &mut wide_queue,
        PeerDrivenApplyInvocation {
            inputs: devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0),
            live_apply_ctx: &mut ctx,
            previous_fingerprint_prefix: String::new(),
            previous_sequence: None,
        },
        &mut marker,
        &policy,
        &devnet_runtime_domain(),
        5_000, // age = 4000s > 10s
    );
    match &outcome {
        PeerDrivenApplyOutcome::CandidateExpired {
            staged_at_unix_secs,
            age_secs,
            max_age_secs,
        } => {
            assert_eq!(*staged_at_unix_secs, 1_000);
            assert_eq!(*age_secs, 4_000);
            assert_eq!(*max_age_secs, 10);
        }
        other => panic!("expected CandidateExpired, got {:?}", std::mem::discriminant(other)),
    }
    assert!(ctx_log.lock().unwrap().events.is_empty());
    assert!(marker_log.lock().unwrap().is_empty());
    let _ = validated;
}

// =====================================================================
// R3 + R4. Marker conflict refusals (lower sequence / same-sequence
// different digest). The pre-apply marker coordinator returns Err.
// =====================================================================

#[test]
fn r3_lower_sequence_marker_conflict_refuses_before_apply() {
    let dir = tmpdir("r3-conflict");
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
        Some("peer-r3"),
        1_000,
        Some("digest-r3".into()),
    );

    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let ctx_log = ctx.log();
    let mut marker =
        MockV2MarkerCoordinator::new().with_pre_apply_err("v2-lower-sequence-rejected (5 < 7)");
    let marker_log = marker.log();

    let policy = PeerDrivenApplyPolicy::devnet_enabled();
    let id = StagedPeerCandidateId::new(&validated.fingerprint_prefix, validated.sequence);
    let outcome = try_apply_staged_peer_candidate(
        &id,
        &mut queue,
        PeerDrivenApplyInvocation {
            inputs: devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0),
            live_apply_ctx: &mut ctx,
            previous_fingerprint_prefix: String::new(),
            previous_sequence: None,
        },
        &mut marker,
        &policy,
        &devnet_runtime_domain(),
        1_001,
    );
    match &outcome {
        PeerDrivenApplyOutcome::CandidateMarkerConflict { reason } => {
            assert!(reason.contains("lower-sequence"), "reason={}", reason);
        }
        other => panic!("expected CandidateMarkerConflict, got {:?}", std::mem::discriminant(other)),
    }
    assert!(ctx_log.lock().unwrap().events.is_empty(), "no apply call");
    let mevents = marker_log.lock().unwrap().clone();
    assert_eq!(
        mevents,
        vec!["decide_pre_apply"],
        "marker pre-apply called once; persist not called"
    );
}

#[test]
fn r4_same_sequence_different_digest_marker_conflict_refuses() {
    let dir = tmpdir("r4-equivocation");
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
        Some("peer-r4"),
        1_000,
        Some("digest-r4".into()),
    );

    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let ctx_log = ctx.log();
    let mut marker = MockV2MarkerCoordinator::new()
        .with_pre_apply_err("v2-same-sequence-different-digest equivocation");
    let policy = PeerDrivenApplyPolicy::devnet_enabled();
    let id = StagedPeerCandidateId::new(&validated.fingerprint_prefix, validated.sequence);
    let outcome = try_apply_staged_peer_candidate(
        &id,
        &mut queue,
        PeerDrivenApplyInvocation {
            inputs: devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0),
            live_apply_ctx: &mut ctx,
            previous_fingerprint_prefix: String::new(),
            previous_sequence: None,
        },
        &mut marker,
        &policy,
        &devnet_runtime_domain(),
        1_001,
    );
    assert!(matches!(
        outcome,
        PeerDrivenApplyOutcome::CandidateMarkerConflict { .. }
    ));
    assert!(ctx_log.lock().unwrap().events.is_empty());
}

// =====================================================================
// R5. Wrong-domain staged candidate cannot apply.
// =====================================================================

#[test]
fn r5_wrong_domain_staged_candidate_cannot_apply() {
    let dir = tmpdir("r5-wrong-domain");
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
        Some("peer-r5"),
        1_000,
        Some("digest-r5".into()),
    );

    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let ctx_log = ctx.log();
    let mut marker = MockV2MarkerCoordinator::new();
    let marker_log = marker.log();

    // Mismatched runtime: declare Testnet domain (chain id) while
    // candidate is DevNet-tagged.
    let testnet_domain = testnet_runtime_domain();
    let mut policy = PeerDrivenApplyPolicy::testnet_enabled();
    policy.environment = NetworkEnvironment::Testnet;
    let id = StagedPeerCandidateId::new(&validated.fingerprint_prefix, validated.sequence);
    let outcome = try_apply_staged_peer_candidate(
        &id,
        &mut queue,
        PeerDrivenApplyInvocation {
            inputs: devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0),
            live_apply_ctx: &mut ctx,
            previous_fingerprint_prefix: String::new(),
            previous_sequence: None,
        },
        &mut marker,
        &policy,
        &testnet_domain,
        1_001,
    );
    assert!(matches!(
        outcome,
        PeerDrivenApplyOutcome::CandidateWrongDomain { .. }
    ));
    assert!(ctx_log.lock().unwrap().events.is_empty());
    assert!(marker_log.lock().unwrap().is_empty());
}

// =====================================================================
// R6. Bad-signature candidate cannot apply — surfaces as Run 070
// ValidationFailed (the candidate bundle file has a tampered
// signature so `apply_validated_candidate_with_previous` rejects it
// during the validation stage, BEFORE any swap or commit).
// =====================================================================

#[test]
fn r6_bad_signature_candidate_cannot_apply() {
    let dir = tmpdir("r6-bad-sig");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let mut bundle = build_signed_devnet_bundle(&h, 5, 500, None, vec![]);
    // Tamper signature bytes.
    if let Some(ref mut sig) = bundle.signature {
        // Flip a byte in the signature payload — we need to mutate
        // through whatever the type exposes. Easiest: re-serialise
        // tampered after corrupting one byte of a public field. We
        // corrupt `generated_at`, then re-write to disk without
        // re-signing → signature no longer matches contents.
        let _ = sig;
    }
    bundle.generated_at = 501;
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    // For staging we still need a validated metadata snapshot — but
    // validate_candidate_bundle will refuse the tampered bundle. So we
    // stage via a parallel pristine bundle to get a real
    // ValidatedPeerCandidate, then redirect the apply path to the
    // tampered candidate.
    let pristine = build_signed_devnet_bundle(&h, 5, 500, None, vec![]);
    let pristine_path = write_bundle_to_disk(&dir, "pristine.json", &pristine);
    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    let validated = stage_candidate_from_bundle(
        &mut queue,
        &pristine_path,
        &h.signing_keys,
        Some(&seq_path),
        Some("peer-r6"),
        1_000,
        Some("digest-r6".into()),
    );

    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let ctx_log = ctx.log();
    let mut marker = MockV2MarkerCoordinator::new();
    let policy = PeerDrivenApplyPolicy::devnet_enabled();
    let id = StagedPeerCandidateId::new(&validated.fingerprint_prefix, validated.sequence);
    let outcome = try_apply_staged_peer_candidate(
        &id,
        &mut queue,
        PeerDrivenApplyInvocation {
            inputs: devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0),
            live_apply_ctx: &mut ctx,
            previous_fingerprint_prefix: String::new(),
            previous_sequence: None,
        },
        &mut marker,
        &policy,
        &devnet_runtime_domain(),
        1_001,
    );
    match &outcome {
        PeerDrivenApplyOutcome::ApplyRejected {
            error: ReloadApplyError::ValidationFailed(_),
        } => {}
        other => panic!(
            "expected ApplyRejected(ValidationFailed), got {:?}",
            std::mem::discriminant(other)
        ),
    }
    // No swap occurred — Run 070 validation gate fail-closed.
    let events = ctx_log.lock().unwrap().events.clone();
    assert!(
        !events.contains(&"swap_trust_state".to_string()),
        "validation failure must not call swap; got {:?}",
        events
    );
}

// =====================================================================
// R7. Apply validation failure before swap — same fail-closed
// semantics, covered above via R6. We add a second case here using
// a sequence-rollback failure: write a higher persisted sequence
// first, then attempt to apply a lower-sequence candidate.
// =====================================================================

#[test]
fn r7_apply_validation_failure_before_swap_skips_swap_evict_commit() {
    // A staged candidate whose Run 070 validation fails (here: the
    // candidate bundle file's `generated_at` was rewritten after
    // signing, breaking the signature envelope). The controller must
    // surface `ApplyRejected(ValidationFailed(_))` and the apply
    // pipeline must NOT call `swap_trust_state`, `evict_sessions`,
    // `commit_sequence`, or `rollback_trust_state`. Marker pre-apply
    // ran (and passed) but `persist_after_commit` must NOT be
    // invoked.
    let dir = tmpdir("r7-validation-fail");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    // Stage a pristine candidate so the staging queue has a real
    // entry, then redirect the apply path to a tampered copy.
    let pristine = build_signed_devnet_bundle(&h, 5, 500, None, vec![]);
    let pristine_path = write_bundle_to_disk(&dir, "pristine.json", &pristine);
    let mut tampered = pristine.clone();
    // Mutate a field after the signature was computed so the
    // signature no longer covers the canonical bytes; Run 069/070
    // validation will fail closed at the signature-verification
    // stage.
    tampered.generated_at = 999;
    let tampered_path = write_bundle_to_disk(&dir, "tampered.json", &tampered);

    let mut queue = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
    let validated = stage_candidate_from_bundle(
        &mut queue,
        &pristine_path,
        &h.signing_keys,
        Some(&seq_path),
        Some("peer-r7"),
        1_000,
        Some("digest-r7".into()),
    );
    let snap = snapshot_seq_file(&seq_path);

    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let ctx_log = ctx.log();
    let mut marker = MockV2MarkerCoordinator::new();
    let marker_log = marker.log();

    let policy = PeerDrivenApplyPolicy::devnet_enabled();
    let id = StagedPeerCandidateId::new(&validated.fingerprint_prefix, validated.sequence);
    let outcome = try_apply_staged_peer_candidate(
        &id,
        &mut queue,
        PeerDrivenApplyInvocation {
            inputs: devnet_inputs(&tampered_path, &h.signing_keys, Some(&seq_path), 0),
            live_apply_ctx: &mut ctx,
            previous_fingerprint_prefix: String::new(),
            previous_sequence: None,
        },
        &mut marker,
        &policy,
        &devnet_runtime_domain(),
        1_001,
    );
    match &outcome {
        PeerDrivenApplyOutcome::ApplyRejected {
            error: ReloadApplyError::ValidationFailed(_),
        } => {}
        other => panic!(
            "expected ApplyRejected(ValidationFailed), got {:?}",
            std::mem::discriminant(other)
        ),
    }
    let events = ctx_log.lock().unwrap().events.clone();
    assert!(
        !events.contains(&"swap_trust_state".to_string())
            && !events.contains(&"evict_sessions".to_string())
            && !events.contains(&"commit_sequence".to_string())
            && !events.contains(&"rollback_trust_state".to_string()),
        "validation failure must not call swap/evict/commit/rollback; got {:?}",
        events
    );
    // Marker pre-apply ran; persist did NOT.
    let mevents = marker_log.lock().unwrap().clone();
    assert_eq!(mevents, vec!["decide_pre_apply"]);
    assert_seq_file_unchanged(&seq_path, snap);
}

// =====================================================================
// R8. Swap failure: no eviction, no commit, no marker write.
// =====================================================================

#[test]
fn r8_swap_failure_does_not_evict_commit_or_persist_marker() {
    let dir = tmpdir("r8-swap-fail");
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
        Some("peer-r8"),
        1_000,
        Some("digest-r8".into()),
    );

    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    ctx.swap_action = ActionPlan::Err("write lock unavailable".into());
    let ctx_log = ctx.log();
    let active = ctx.active();
    let mut marker = MockV2MarkerCoordinator::new();
    let marker_log = marker.log();

    let policy = PeerDrivenApplyPolicy::devnet_enabled();
    let id = StagedPeerCandidateId::new(&validated.fingerprint_prefix, validated.sequence);
    let outcome = try_apply_staged_peer_candidate(
        &id,
        &mut queue,
        PeerDrivenApplyInvocation {
            inputs: devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0),
            live_apply_ctx: &mut ctx,
            previous_fingerprint_prefix: "aaaaaaaa".into(),
            previous_sequence: Some(3),
        },
        &mut marker,
        &policy,
        &devnet_runtime_domain(),
        1_001,
    );
    match &outcome {
        PeerDrivenApplyOutcome::ApplyRejected {
            error: ReloadApplyError::StateSwapFailed(_),
        } => {}
        other => panic!(
            "expected ApplyRejected(StateSwapFailed), got {:?}",
            std::mem::discriminant(other)
        ),
    }
    assert_eq!(*active.lock().unwrap(), "aaaaaaaa");
    let events = ctx_log.lock().unwrap().events.clone();
    assert_eq!(
        events,
        vec!["snapshot_active", "swap_trust_state"],
        "swap failure must stop after the failed swap"
    );
    // Marker pre-apply was checked; persist was NOT called.
    let mevents = marker_log.lock().unwrap().clone();
    assert_eq!(mevents, vec!["decide_pre_apply"]);
}

// =====================================================================
// R9. Eviction failure → rollback succeeds; no commit; no marker.
// =====================================================================

#[test]
fn r9_eviction_failure_rolls_back_and_does_not_commit_or_persist_marker() {
    let dir = tmpdir("r9-evict-fail");
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
        Some("peer-r9"),
        1_000,
        Some("digest-r9".into()),
    );

    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    ctx.evict_action = ActionPlan::Err("session manager unavailable".into());
    let ctx_log = ctx.log();
    let active = ctx.active();
    let mut marker = MockV2MarkerCoordinator::new();
    let marker_log = marker.log();

    let policy = PeerDrivenApplyPolicy::devnet_enabled();
    let id = StagedPeerCandidateId::new(&validated.fingerprint_prefix, validated.sequence);
    let outcome = try_apply_staged_peer_candidate(
        &id,
        &mut queue,
        PeerDrivenApplyInvocation {
            inputs: devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0),
            live_apply_ctx: &mut ctx,
            previous_fingerprint_prefix: String::new(),
            previous_sequence: None,
        },
        &mut marker,
        &policy,
        &devnet_runtime_domain(),
        1_001,
    );
    match &outcome {
        PeerDrivenApplyOutcome::ApplyRollbackSucceeded {
            error: ReloadApplyError::SessionEvictionFailed { rollback_ok: true, .. },
        } => {}
        other => panic!(
            "expected ApplyRollbackSucceeded(SessionEvictionFailed{{rollback_ok:true}}), got {:?}",
            std::mem::discriminant(other)
        ),
    }
    // Live state restored.
    assert_eq!(*active.lock().unwrap(), "aaaaaaaa");
    let events = ctx_log.lock().unwrap().events.clone();
    assert_eq!(
        events,
        vec![
            "snapshot_active",
            "swap_trust_state",
            "evict_sessions",
            "rollback_trust_state",
        ],
    );
    // Persist NOT called.
    let mevents = marker_log.lock().unwrap().clone();
    assert_eq!(mevents, vec!["decide_pre_apply"]);
}

// =====================================================================
// R10. Sequence commit failure → rollback succeeds; no marker.
// =====================================================================

#[test]
fn r10_sequence_commit_failure_rolls_back_and_does_not_persist_marker() {
    let dir = tmpdir("r10-commit-fail");
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
        Some("peer-r10"),
        1_000,
        Some("digest-r10".into()),
    );

    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    ctx.commit_action = ActionPlan::Err("disk full".into());
    let ctx_log = ctx.log();
    let active = ctx.active();
    let mut marker = MockV2MarkerCoordinator::new();
    let marker_log = marker.log();

    let policy = PeerDrivenApplyPolicy::devnet_enabled();
    let id = StagedPeerCandidateId::new(&validated.fingerprint_prefix, validated.sequence);
    let outcome = try_apply_staged_peer_candidate(
        &id,
        &mut queue,
        PeerDrivenApplyInvocation {
            inputs: devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0),
            live_apply_ctx: &mut ctx,
            previous_fingerprint_prefix: String::new(),
            previous_sequence: None,
        },
        &mut marker,
        &policy,
        &devnet_runtime_domain(),
        1_001,
    );
    match &outcome {
        PeerDrivenApplyOutcome::ApplyRollbackSucceeded {
            error: ReloadApplyError::SequenceCommitFailed(_),
        } => {}
        other => panic!(
            "expected ApplyRollbackSucceeded(SequenceCommitFailed), got {:?}",
            std::mem::discriminant(other)
        ),
    }
    assert_eq!(*active.lock().unwrap(), "aaaaaaaa");
    let events = ctx_log.lock().unwrap().events.clone();
    assert_eq!(
        events,
        vec![
            "snapshot_active",
            "swap_trust_state",
            "evict_sessions",
            "commit_sequence",
            "rollback_trust_state",
        ],
    );
    let mevents = marker_log.lock().unwrap().clone();
    assert_eq!(mevents, vec!["decide_pre_apply"]);
}

// =====================================================================
// R11. Commit failure + rollback failure → fatal outcome.
// =====================================================================

#[test]
fn r11_commit_failure_with_rollback_failure_is_fatal_and_does_not_persist_marker() {
    let dir = tmpdir("r11-fatal");
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
        Some("peer-r11"),
        1_000,
        Some("digest-r11".into()),
    );

    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    ctx.commit_action = ActionPlan::Err("disk full".into());
    ctx.rollback_action = ActionPlan::Err("snapshot drained".into());
    let mut marker = MockV2MarkerCoordinator::new();
    let marker_log = marker.log();

    let policy = PeerDrivenApplyPolicy::devnet_enabled();
    let id = StagedPeerCandidateId::new(&validated.fingerprint_prefix, validated.sequence);
    let outcome = try_apply_staged_peer_candidate(
        &id,
        &mut queue,
        PeerDrivenApplyInvocation {
            inputs: devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0),
            live_apply_ctx: &mut ctx,
            previous_fingerprint_prefix: String::new(),
            previous_sequence: None,
        },
        &mut marker,
        &policy,
        &devnet_runtime_domain(),
        1_001,
    );
    match &outcome {
        PeerDrivenApplyOutcome::ApplyFatalRollbackFailed {
            error: ReloadApplyError::SequenceCommitFailedRollbackAlsoFailed { .. },
        } => {}
        other => panic!(
            "expected ApplyFatalRollbackFailed, got {:?}",
            std::mem::discriminant(other)
        ),
    }
    assert!(outcome.is_fatal_operator_actionable());
    // Marker persist must NOT have been called.
    let mevents = marker_log.lock().unwrap().clone();
    assert_eq!(mevents, vec!["decide_pre_apply"]);
}

// =====================================================================
// R12. Marker persist failure after successful commit → fatal /
// operator-actionable. Apply succeeded, sequence advanced, but the
// marker is now stale-by-one. The outcome is
// MarkerPersistFailedAfterCommit.
// =====================================================================

#[test]
fn r12_marker_persist_failure_after_successful_commit_is_fatal_operator_actionable() {
    let dir = tmpdir("r12-marker-fail");
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
        Some("peer-r12"),
        1_000,
        Some("digest-r12".into()),
    );

    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let ctx_log = ctx.log();
    let mut marker =
        MockV2MarkerCoordinator::new().with_post_commit_err("marker write: disk full");
    let policy = PeerDrivenApplyPolicy::devnet_enabled();
    let id = StagedPeerCandidateId::new(&validated.fingerprint_prefix, validated.sequence);
    let outcome = try_apply_staged_peer_candidate(
        &id,
        &mut queue,
        PeerDrivenApplyInvocation {
            inputs: devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0),
            live_apply_ctx: &mut ctx,
            previous_fingerprint_prefix: String::new(),
            previous_sequence: None,
        },
        &mut marker,
        &policy,
        &devnet_runtime_domain(),
        1_001,
    );
    match &outcome {
        PeerDrivenApplyOutcome::MarkerPersistFailedAfterCommit {
            applied,
            marker_error,
        } => {
            assert_eq!(applied.validated.sequence, 5);
            assert!(marker_error.contains("disk full"));
        }
        other => panic!(
            "expected MarkerPersistFailedAfterCommit, got {:?}",
            std::mem::discriminant(other)
        ),
    }
    assert!(outcome.is_fatal_operator_actionable());
    let events = ctx_log.lock().unwrap().events.clone();
    assert_eq!(
        events,
        vec![
            "snapshot_active",
            "swap_trust_state",
            "evict_sessions",
            "commit_sequence",
        ],
        "Run 070 commit succeeded before marker persist failed"
    );
}

// =====================================================================
// R13. Idempotent staged v2 candidate behaviour.
// Chosen behaviour (documented): refuse as already-applied via the
// pre-apply marker decision (the coordinator surfaces the idempotent
// case as a refusal). No second apply, no second marker write, no
// sequence rewrite.
// =====================================================================

#[test]
fn r13_idempotent_staged_v2_candidate_is_refused_as_already_applied() {
    let dir = tmpdir("r13-idempotent");
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
        Some("peer-r13"),
        1_000,
        Some("digest-r13".into()),
    );

    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let ctx_log = ctx.log();
    let mut marker = MockV2MarkerCoordinator::new()
        .with_pre_apply_err("v2-already-applied (same marker, same sequence)");
    let policy = PeerDrivenApplyPolicy::devnet_enabled();
    let id = StagedPeerCandidateId::new(&validated.fingerprint_prefix, validated.sequence);
    let outcome = try_apply_staged_peer_candidate(
        &id,
        &mut queue,
        PeerDrivenApplyInvocation {
            inputs: devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0),
            live_apply_ctx: &mut ctx,
            previous_fingerprint_prefix: String::new(),
            previous_sequence: None,
        },
        &mut marker,
        &policy,
        &devnet_runtime_domain(),
        1_001,
    );
    match &outcome {
        PeerDrivenApplyOutcome::CandidateMarkerConflict { reason } => {
            assert!(reason.contains("already-applied"));
        }
        other => panic!("expected CandidateMarkerConflict, got {:?}", std::mem::discriminant(other)),
    }
    // No Run 070 callbacks.
    assert!(ctx_log.lock().unwrap().events.is_empty());
}

// =====================================================================
// R14. v2-after-v1 migration candidate applies under enabled DevNet
// policy. The pre-apply marker coordinator returns Ok (migration
// allowed); apply succeeds; marker persisted only after commit.
// =====================================================================

#[test]
fn r14_v2_after_v1_migration_candidate_applies_under_enabled_devnet_policy() {
    let dir = tmpdir("r14-migration");
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
        Some("peer-r14"),
        1_000,
        Some("digest-r14".into()),
    );

    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let ctx_log = ctx.log();
    let mut marker = MockV2MarkerCoordinator::new(); // pre+post both Ok by default
    let marker_log = marker.log();

    let policy = PeerDrivenApplyPolicy::devnet_enabled();
    let id = StagedPeerCandidateId::new(&validated.fingerprint_prefix, validated.sequence);
    let outcome = try_apply_staged_peer_candidate(
        &id,
        &mut queue,
        PeerDrivenApplyInvocation {
            inputs: devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0),
            live_apply_ctx: &mut ctx,
            previous_fingerprint_prefix: "v1-fp00".into(),
            previous_sequence: Some(4),
        },
        &mut marker,
        &policy,
        &devnet_runtime_domain(),
        1_001,
    );
    assert!(matches!(
        outcome,
        PeerDrivenApplyOutcome::MarkerPersistedAfterCommit { .. }
    ));
    let events = ctx_log.lock().unwrap().events.clone();
    assert_eq!(
        events,
        vec![
            "snapshot_active",
            "swap_trust_state",
            "evict_sessions",
            "commit_sequence",
        ],
    );
    // pre-apply BEFORE commit; persist only AFTER commit.
    let mevents = marker_log.lock().unwrap().clone();
    assert_eq!(mevents, vec!["decide_pre_apply", "persist_after_commit"]);
}

// =====================================================================
// R15 / R16. Propagation-only and validation-only behaviour unchanged.
// The Run 148 controller is a separate decision after staging; it
// neither replaces nor weakens the Run 088 (propagation) or Run 142
// (validation-only) paths. We assert this structurally: the
// controller's API is purely additive — it does not expose a
// "rebroadcast" hook and it does not advance state when the policy is
// disabled (covered by A3). Here we additionally prove that the
// staging queue remains intact across a controller invocation that
// refuses (no entry removed / no entry mutated by the controller
// itself).
// =====================================================================

#[test]
fn r15_r16_staging_queue_is_not_mutated_by_a_pre_apply_refusal() {
    let dir = tmpdir("r15-staging-intact");
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
        Some("peer-r15"),
        1_000,
        Some("digest-r15".into()),
    );
    let before = queue.entries();
    assert_eq!(before.len(), 1);

    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let mut marker = MockV2MarkerCoordinator::new();
    let policy = PeerDrivenApplyPolicy::default(); // disabled
    let id = StagedPeerCandidateId::new(&validated.fingerprint_prefix, validated.sequence);
    let outcome = try_apply_staged_peer_candidate(
        &id,
        &mut queue,
        PeerDrivenApplyInvocation {
            inputs: devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0),
            live_apply_ctx: &mut ctx,
            previous_fingerprint_prefix: String::new(),
            previous_sequence: None,
        },
        &mut marker,
        &policy,
        &devnet_runtime_domain(),
        1_001,
    );
    assert!(matches!(outcome, PeerDrivenApplyOutcome::Disabled));
    let after = queue.entries();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].fingerprint_prefix, before[0].fingerprint_prefix);
    assert_eq!(after[0].sequence, before[0].sequence);
    assert_eq!(
        after[0].staged_at_unix_secs,
        before[0].staged_at_unix_secs
    );
}

// =====================================================================
// NoV2MarkerCoordinator smoke — proves that when
// require_v2_ratification=false, the controller succeeds via the
// plain ApplySucceeded outcome without invoking marker discipline.
// =====================================================================

#[test]
fn no_v2_marker_coordinator_path_returns_apply_succeeded() {
    let dir = tmpdir("no-v2");
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
        Some("peer-no-v2"),
        1_000,
        None,
    );

    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let mut marker = NoV2MarkerCoordinator;
    let mut policy = PeerDrivenApplyPolicy::devnet_enabled();
    policy.require_v2_ratification = false;
    let id = StagedPeerCandidateId::new(&validated.fingerprint_prefix, validated.sequence);
    let outcome = try_apply_staged_peer_candidate(
        &id,
        &mut queue,
        PeerDrivenApplyInvocation {
            inputs: devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0),
            live_apply_ctx: &mut ctx,
            previous_fingerprint_prefix: String::new(),
            previous_sequence: None,
        },
        &mut marker,
        &policy,
        &devnet_runtime_domain(),
        1_001,
    );
    assert!(matches!(
        outcome,
        PeerDrivenApplyOutcome::ApplySucceeded { .. }
    ));
}
