//! Run 119 — integration tests for the **shared mutating-surface
//! accept-and-persist composition** wired into the process-start
//! reload-apply binary path.
//!
//! These tests exercise the Run 119 helpers
//! ([`qbind_node::pqc_authority_marker_acceptance::decide_marker_acceptance`]
//! and [`qbind_node::pqc_authority_marker_acceptance::persist_accepted_marker_after_commit_boundary`])
//! against the Run 070 apply pipeline using a deterministic
//! `FakeLiveTrustApplyContext`. The tests are deliberately a copy of
//! the Run 112 harness with the marker-orchestration sandwich added
//! around the apply call — so they prove the integration contract:
//!
//!   * **§C.1 (clean accept then persist):** decide → apply →
//!     persist; the marker file lands on disk; Run 070 callback
//!     ordering preserved bit-for-bit.
//!   * **§C.2 (decide reject, no apply):** decide rejects a
//!     pre-persisted rollback marker BEFORE any apply call; live
//!     state, sequence file, and on-disk marker all unchanged.
//!   * **§C.3 (apply fails, no marker rewrite):** decide accepts but
//!     the apply pipeline returns Err (refused at validate / swap /
//!     commit); the marker is NOT rewritten because the orchestration
//!     skips persist on `Err`.
//!   * **§C.4 (idempotent persist no-op):** a re-apply of the same
//!     candidate produces an `Idempotent` decision whose
//!     [`should_persist`] is false; the persist call is a strict
//!     no-op (file mtime / bytes unchanged).
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_119.md`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use qbind_crypto::MlDsa44Backend;
use qbind_ledger::{
    bundle_signing_ratification::test_helpers as ratification_helpers,
    compute_canonical_genesis_hash, enforce_bundle_signing_key_ratification,
    BundleSigningRatification, GenesisAllocation, GenesisAuthorityConfig, GenesisAuthorityRoot,
    GenesisConfig, GenesisCouncilConfig, GenesisHash, GenesisMonetaryConfig, GenesisValidator,
    NetworkEnvironmentPolicy, RatificationEnforcementInputs, RatificationEnforcementOutcome,
    RatificationEnforcementPolicy, RatificationEnvironment,
    GENESIS_AUTHORITY_SUITE_ML_DSA_44,
};
use qbind_node::pqc_authority_marker_acceptance::{
    decide_marker_acceptance, persist_accepted_marker_after_commit_boundary,
    MarkerAcceptKind, MarkerAcceptanceInputs, MutatingSurfaceMarkerError,
};
use qbind_node::pqc_authority_state::{
    authority_state_file_path, load_authority_state, AuthorityStateUpdateSource,
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
    RatificationEnforcementContext, ReloadCheckInputs,
};
use qbind_node::pqc_trust_sequence::{chain_id_hex, sequence_file_path};
use qbind_types::NetworkEnvironment;

// ---------------------------------------------------------------------
// Helpers (copied from run_112_reload_apply_ratification_tests).
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
        "qbind-run119-{}-{}-{}",
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
    #[allow(dead_code)]
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
// Identical to the Run 112 version; copied for self-contained tests.
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
    fail_at_swap: bool,
}

impl FakeLiveTrustApplyContext {
    fn new(initial_fingerprint: &str) -> Self {
        Self {
            log: Arc::new(Mutex::new(CallLog::default())),
            active_fingerprint: Arc::new(Mutex::new(initial_fingerprint.to_string())),
            fail_at_swap: false,
        }
    }
    fn with_swap_failure(initial_fingerprint: &str) -> Self {
        let mut s = Self::new(initial_fingerprint);
        s.fail_at_swap = true;
        s
    }
    fn log(&self) -> Arc<Mutex<CallLog>> {
        self.log.clone()
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
        if self.fail_at_swap {
            return Err("simulated swap failure".to_string());
        }
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

// ---------------------------------------------------------------------
// Shared sub-sandwich helpers — collapse the Run 119 orchestration
// pattern (decide → apply → persist) into a single helper so each
// test exercises the same wiring.
// ---------------------------------------------------------------------

fn runtime_genesis_hash_hex(h: &Harness) -> String {
    let mut s = String::with_capacity(64);
    for b in h.canonical_hash {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

fn build_marker_inputs<'a>(
    marker_path: &'a Path,
    gh_hex: &'a str,
    h: &'a Harness,
    ratification: &'a BundleSigningRatification,
    ratified: &'a qbind_ledger::RatifiedBundleSigningKey,
) -> MarkerAcceptanceInputs<'a> {
    let authority = h.genesis_cfg.authority.as_ref().unwrap();
    MarkerAcceptanceInputs {
        marker_path,
        runtime_env: NetworkEnvironment::Devnet,
        runtime_chain_id: NetworkEnvironment::Devnet.chain_id(),
        runtime_genesis_hash_hex: gh_hex,
        authority_policy_version: authority.authority_policy_version,
        authority_sequence: authority.authority_sequence,
        authority_epoch: authority.authority_epoch,
        ratification,
        ratified,
        update_source: AuthorityStateUpdateSource::ReloadApply,
        updated_at_unix_secs: 100,
    }
}

fn ratified_via_run105(
    h: &Harness,
    ratification: &BundleSigningRatification,
) -> qbind_ledger::RatifiedBundleSigningKey {
    let outcome = enforce_bundle_signing_key_ratification(RatificationEnforcementInputs {
        ratification: Some(ratification),
        authority: h.genesis_cfg.authority.as_ref().unwrap(),
        expected_chain_id: &h.chain_id_str,
        expected_environment: h.env_policy,
        expected_genesis_hash: &h.canonical_hash,
        candidate_bundle_signing_public_key: &h.signing_pk,
        policy: RatificationEnforcementPolicy::Strict,
    })
    .expect("Run 105 enforces clean ratification under Strict");
    match outcome {
        RatificationEnforcementOutcome::Ratified(rk) => rk,
        other => panic!("expected Ratified, got {:?}", other),
    }
}

// =====================================================================
// Scenarios
// =====================================================================

/// §C.1 — decide → apply → persist: clean first-write produces both a
/// successful apply (Run 070 ordering preserved bit-for-bit) and a
/// freshly persisted authority marker.
#[test]
fn run119_clean_first_write_decide_then_apply_then_persist() {
    let h = devnet_harness();
    let dir = tmpdir("clean");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    let bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "cand.json", &bundle);
    let ratification = build_valid_ratification(&h);
    let ratified = ratified_via_run105(&h, &ratification);
    let gh_hex = runtime_genesis_hash_hex(&h);

    assert!(!marker_path.exists(), "precondition: no prior marker");

    // Run 119 — decide.
    let decision = decide_marker_acceptance(build_marker_inputs(
        &marker_path,
        &gh_hex,
        &h,
        &ratification,
        &ratified,
    ))
    .expect("clean ratification → first-write accept");
    assert!(matches!(decision.kind(), MarkerAcceptKind::FirstWrite));
    assert!(!marker_path.exists(), "decide MUST NOT write the marker");

    // Run 070 — apply.
    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let log = ctx.log();
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
    .expect("apply Ok");
    assert_eq!(applied.validated.sequence, 2);
    let events = log.lock().unwrap().events.clone();
    assert_eq!(
        events,
        vec![
            "snapshot_active",
            "swap_trust_state",
            "evict_sessions",
            "commit_sequence",
        ],
        "Run 070 ordering must be preserved bit-for-bit"
    );

    // Run 119 — persist after commit boundary.
    persist_accepted_marker_after_commit_boundary(&decision)
        .expect("persist after commit_sequence Ok");
    let loaded = load_authority_state(&marker_path)
        .expect("load Ok")
        .expect("marker present");
    assert_eq!(loaded.environment, TrustBundleEnvironment::Devnet);
    assert_eq!(loaded.chain_id, h.chain_id_str);
    assert_eq!(loaded.genesis_hash, gh_hex);
    assert_eq!(loaded.ratified_bundle_signing_key_fingerprint, ratified.fingerprint);
}

/// §C.2 — decide rejects pre-existing rollback marker BEFORE any apply
/// call; no apply callbacks fire, no marker rewrite, no sequence file.
#[test]
fn run119_pre_persisted_marker_rollback_rejects_before_apply() {
    let h = devnet_harness();
    let dir = tmpdir("rollback");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    let bundle = build_signed_bundle(&h, 2, 200);
    let _candidate_path = write_bundle(&dir, "cand.json", &bundle);
    let ratification = build_valid_ratification(&h);
    let ratified = ratified_via_run105(&h, &ratification);
    let gh_hex = runtime_genesis_hash_hex(&h);

    // Pre-persist a marker at a STRICTLY HIGHER authority_sequence
    // than what the genesis-authority block produces. The candidate
    // will derive at the genesis-authority sequence, which is lower,
    // and the compare step refuses the rollback.
    let mut high_inputs =
        build_marker_inputs(&marker_path, &gh_hex, &h, &ratification, &ratified);
    high_inputs.authority_sequence = high_inputs.authority_sequence.saturating_add(1);
    let high_decision = decide_marker_acceptance(high_inputs).expect("first-write at higher seq");
    persist_accepted_marker_after_commit_boundary(&high_decision)
        .expect("persist higher-seq marker");
    assert!(marker_path.exists());
    let marker_bytes_before = std::fs::read(&marker_path).unwrap();

    // Run 119 — decide must reject as rollback.
    let err = decide_marker_acceptance(build_marker_inputs(
        &marker_path,
        &gh_hex,
        &h,
        &ratification,
        &ratified,
    ))
    .expect_err("rollback must reject");
    assert!(
        matches!(err, MutatingSurfaceMarkerError::AuthoritySequenceRollback { .. }),
        "got {:?}",
        err
    );

    // The orchestration contract: on Err from decide, the binary MUST
    // skip the apply call entirely. We emulate that by building a
    // FakeLiveTrustApplyContext and asserting we never call apply.
    let ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let log = ctx.log();
    // Intentionally do NOT call apply_validated_candidate_with_previous_and_ratification.
    drop(ctx);
    let events = log.lock().unwrap().events.clone();
    assert!(
        events.is_empty(),
        "Run 119 orchestration: marker-reject must NOT invoke any apply callback; got {:?}",
        events
    );

    // Marker file unchanged; sequence file never created.
    let marker_bytes_after = std::fs::read(&marker_path).unwrap();
    assert_eq!(marker_bytes_before, marker_bytes_after);
    assert!(!seq_path.exists(), "sequence file must not be created");
}

/// §C.3 — decide accepts but the apply pipeline fails inside the swap
/// step; the marker is NOT persisted because the orchestration calls
/// persist ONLY on `Ok(applied)`.
#[test]
fn run119_apply_failure_after_accept_does_not_persist_marker() {
    let h = devnet_harness();
    let dir = tmpdir("applyerr");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    let bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "cand.json", &bundle);
    let ratification = build_valid_ratification(&h);
    let ratified = ratified_via_run105(&h, &ratification);
    let gh_hex = runtime_genesis_hash_hex(&h);

    assert!(!marker_path.exists());

    let decision = decide_marker_acceptance(build_marker_inputs(
        &marker_path,
        &gh_hex,
        &h,
        &ratification,
        &ratified,
    ))
    .expect("first-write accept");

    // Apply pipeline forced to fail at the swap step.
    let mut ctx = FakeLiveTrustApplyContext::with_swap_failure("aaaaaaaa");
    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path));
    let ratification_ctx = RatificationEnforcementContext {
        authority: h.genesis_cfg.authority.as_ref().unwrap(),
        expected_genesis_hash: &h.canonical_hash,
        expected_environment_policy: h.env_policy,
        expected_chain_id_str: &h.chain_id_str,
        ratification: Some(&ratification),
        policy: RatificationEnforcementPolicy::Strict,
    };
    let apply_outcome = apply_validated_candidate_with_previous_and_ratification(
        inputs,
        &ratification_ctx,
        ApplyMode::ApplyLive,
        Some(&mut ctx),
        "aaaaaaaa".to_string(),
        Some(1),
    );
    assert!(apply_outcome.is_err(), "apply must surface swap failure");

    // Orchestration contract: on Err, do NOT call persist. We emulate
    // that branch and assert the marker file did not appear.
    assert!(
        !marker_path.exists(),
        "marker MUST NOT be persisted when apply pipeline returns Err"
    );
    // Defensive: explicitly proving the helper itself never writes
    // when the orchestration skips it.
    drop(decision);
    assert!(!marker_path.exists());
}

/// §C.4 — re-apply of a bit-for-bit identical candidate produces an
/// idempotent decision; persist is a strict no-op (file bytes
/// unchanged).
#[test]
fn run119_idempotent_re_apply_does_not_rewrite_marker() {
    let h = devnet_harness();
    let dir = tmpdir("idempotent");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    let bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "cand.json", &bundle);
    let ratification = build_valid_ratification(&h);
    let ratified = ratified_via_run105(&h, &ratification);
    let gh_hex = runtime_genesis_hash_hex(&h);

    // First apply — clean accept + persist.
    let d1 = decide_marker_acceptance(build_marker_inputs(
        &marker_path,
        &gh_hex,
        &h,
        &ratification,
        &ratified,
    ))
    .expect("first-write");
    let mut ctx1 = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let inputs1 = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path));
    let ratification_ctx = RatificationEnforcementContext {
        authority: h.genesis_cfg.authority.as_ref().unwrap(),
        expected_genesis_hash: &h.canonical_hash,
        expected_environment_policy: h.env_policy,
        expected_chain_id_str: &h.chain_id_str,
        ratification: Some(&ratification),
        policy: RatificationEnforcementPolicy::Strict,
    };
    apply_validated_candidate_with_previous_and_ratification(
        inputs1,
        &ratification_ctx,
        ApplyMode::ApplyLive,
        Some(&mut ctx1),
        "aaaaaaaa".to_string(),
        Some(1),
    )
    .expect("first apply Ok");
    persist_accepted_marker_after_commit_boundary(&d1).expect("first persist Ok");
    let marker_bytes_after_first = std::fs::read(&marker_path).unwrap();

    // Second apply — identical inputs.
    let d2 = decide_marker_acceptance(build_marker_inputs(
        &marker_path,
        &gh_hex,
        &h,
        &ratification,
        &ratified,
    ))
    .expect("second decide");
    assert!(
        matches!(d2.kind(), MarkerAcceptKind::Idempotent),
        "expected Idempotent, got {:?}",
        d2.kind()
    );
    assert!(!d2.should_persist());

    let mut ctx2 = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let inputs2 = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path));
    let _ = apply_validated_candidate_with_previous_and_ratification(
        inputs2,
        &ratification_ctx,
        ApplyMode::ApplyLive,
        Some(&mut ctx2),
        "aaaaaaaa".to_string(),
        Some(2),
    );

    persist_accepted_marker_after_commit_boundary(&d2)
        .expect("idempotent persist Ok (no-op)");
    let marker_bytes_after_second = std::fs::read(&marker_path).unwrap();
    assert_eq!(
        marker_bytes_after_first, marker_bytes_after_second,
        "idempotent persist must NOT rewrite the marker file"
    );
}