//! Run 134 — integration tests for the **v2 mutating-surface
//! accept-and-persist composition** wired into the process-start
//! reload-apply binary path.
//!
//! These tests exercise the Run 134 helpers
//! ([`qbind_node::pqc_authority_marker_acceptance::decide_marker_acceptance_v2`]
//! and
//! [`qbind_node::pqc_authority_marker_acceptance::persist_accepted_v2_marker_after_commit_boundary`])
//! against the Run 070 apply pipeline using a deterministic
//! `FakeLiveTrustApplyContext`, mirroring the Run 119 harness shape.
//!
//! Scope:
//!
//!   * **§C.1 (clean v2 first-write):** decide_v2 → apply → persist_v2;
//!     the on-disk versioned marker lands as v2; Run 070 callback
//!     ordering preserved bit-for-bit.
//!   * **§C.2 (decide_v2 rejects rollback):** a pre-persisted higher
//!     `authority_domain_sequence` v2 marker fail-closes the decide step
//!     BEFORE any apply callback fires; the on-disk marker is byte-for-
//!     byte unchanged and the sequence file is never written.
//!   * **§C.3 (apply fails, no v2 marker rewrite):** decide_v2 accepts
//!     but the apply pipeline returns Err at the swap stage; the marker
//!     is NOT persisted because the orchestration skips persist on
//!     `Err`.
//!   * **§C.4 (idempotent v2 persist no-op):** a re-apply of the same
//!     v2 candidate produces an `Idempotent` decision whose
//!     [`should_persist`] is false; the persist call is a strict no-op
//!     (file bytes unchanged).
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_134.md`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use qbind_crypto::MlDsa44Backend;
use qbind_ledger::{
    bundle_signing_ratification::v2_test_helpers as ratification_v2_helpers,
    compute_canonical_genesis_hash, BundleSigningRatificationV2,
    BundleSigningRatificationV2Action, GenesisAllocation, GenesisAuthorityConfig,
    GenesisAuthorityRoot, GenesisConfig, GenesisCouncilConfig, GenesisHash,
    GenesisMonetaryConfig, GenesisValidator, NetworkEnvironmentPolicy,
    RatificationEnvironment, GENESIS_AUTHORITY_SUITE_ML_DSA_44,
};
use qbind_node::pqc_authority_marker_acceptance::{
    decide_marker_acceptance_v2, persist_accepted_v2_marker_after_commit_boundary,
    MarkerAcceptKindV2, MarkerAcceptanceV2Inputs, MutatingSurfaceMarkerV2Error,
};
use qbind_node::pqc_authority_state::{
    authority_state_file_path, load_authority_state_versioned, AuthorityStateUpdateSource,
    PersistentAuthorityStateRecordVersioned,
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
    apply_validated_candidate_with_previous, ApplyMode, LiveTrustApplyContext,
    ReloadCheckInputs,
};
use qbind_node::pqc_trust_sequence::{chain_id_hex, sequence_file_path};
use qbind_types::NetworkEnvironment;

// ---------------------------------------------------------------------
// Helpers (closely mirror the Run 119 harness).
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
        "qbind-run134-{}-{}-{}",
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

fn build_valid_v2_ratification(h: &Harness, seq: u64) -> BundleSigningRatificationV2 {
    let authority = h.genesis_cfg.authority.as_ref().unwrap();
    let policy_version = authority.authority_policy_version;
    ratification_v2_helpers::build_signed_ratification_v2(
        &h.chain_id_str,
        RatificationEnvironment::Devnet,
        h.canonical_hash,
        policy_version,
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

fn runtime_genesis_hash_hex(h: &Harness) -> String {
    let mut s = String::with_capacity(64);
    for b in h.canonical_hash {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
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

fn build_marker_v2_inputs<'a>(
    marker_path: &'a Path,
    gh_hex: &'a str,
    ratification: &'a BundleSigningRatificationV2,
    ratified: &'a qbind_ledger::RatifiedBundleSigningKeyV2,
) -> MarkerAcceptanceV2Inputs<'a> {
    MarkerAcceptanceV2Inputs {
        marker_path,
        runtime_env: NetworkEnvironment::Devnet,
        runtime_chain_id: NetworkEnvironment::Devnet.chain_id(),
        runtime_genesis_hash_hex: gh_hex,
        ratification,
        ratified,
        update_source: AuthorityStateUpdateSource::ReloadApply,
        updated_at_unix_secs: 100,
    }
}

// ---------------------------------------------------------------------
// FakeLiveTrustApplyContext (deterministic; records every callback).
// Identical to the Run 119 fake.
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

// =====================================================================
// Scenarios
// =====================================================================

/// §C.1 — v2 clean first-write: decide_v2 → apply → persist_v2.
#[test]
fn run134_clean_v2_first_write_decide_then_apply_then_persist() {
    let h = devnet_harness();
    let dir = tmpdir("clean");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    let bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "cand.json", &bundle);
    let ratification = build_valid_v2_ratification(&h, 5);
    let ratified = ratified_v2(&h, &ratification);
    let gh_hex = runtime_genesis_hash_hex(&h);

    assert!(!marker_path.exists(), "precondition: no prior marker");

    // Run 134 — decide v2.
    let decision = decide_marker_acceptance_v2(build_marker_v2_inputs(
        &marker_path,
        &gh_hex,
        &ratification,
        &ratified,
    ))
    .expect("clean v2 ratification -> first-v2-write accept");
    assert!(matches!(decision.kind(), MarkerAcceptKindV2::FirstV2Write));
    assert!(decision.should_persist());
    assert!(!marker_path.exists(), "decide_v2 MUST NOT write the marker");

    // Run 070 — apply (without v1 ratification context; the Run 134
    // wiring strips the v1 enforcement context on the v2 path).
    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let log = ctx.log();
    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path));
    let applied = apply_validated_candidate_with_previous(
        inputs,
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
        "Run 070 ordering must be preserved bit-for-bit on the v2 path"
    );

    // Run 134 — persist v2 marker after commit boundary.
    persist_accepted_v2_marker_after_commit_boundary(&decision)
        .expect("persist v2 after commit_sequence Ok");

    let loaded = load_authority_state_versioned(&marker_path)
        .expect("load Ok")
        .expect("marker present");
    match loaded {
        PersistentAuthorityStateRecordVersioned::V2(v2) => {
            assert_eq!(v2.environment, TrustBundleEnvironment::Devnet);
            assert_eq!(v2.chain_id, h.chain_id_str);
            assert_eq!(v2.genesis_hash, gh_hex);
            assert_eq!(v2.latest_authority_domain_sequence, 5);
            assert_eq!(
                v2.latest_lifecycle_action,
                BundleSigningRatificationV2Action::Ratify
            );
            assert!(v2.previous_bundle_signing_key_fingerprint.is_none());
            assert!(v2.revoked_key_metadata.is_none());
            assert_eq!(v2.last_update_source, AuthorityStateUpdateSource::ReloadApply);
        }
        other => panic!("expected V2 marker on disk, got {:?}", other),
    }
}

/// §C.2 — pre-persisted higher-sequence v2 marker rejects rollback
/// BEFORE any apply call.
#[test]
fn run134_pre_persisted_v2_marker_rollback_rejects_before_apply() {
    let h = devnet_harness();
    let dir = tmpdir("rollback");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    let bundle = build_signed_bundle(&h, 2, 200);
    let _candidate_path = write_bundle(&dir, "cand.json", &bundle);
    let gh_hex = runtime_genesis_hash_hex(&h);

    // Pre-persist a v2 marker at a STRICTLY HIGHER sequence (7).
    let high_ratification = build_valid_v2_ratification(&h, 7);
    let high_ratified = ratified_v2(&h, &high_ratification);
    let high_decision = decide_marker_acceptance_v2(build_marker_v2_inputs(
        &marker_path,
        &gh_hex,
        &high_ratification,
        &high_ratified,
    ))
    .expect("higher-seq v2 first-write");
    persist_accepted_v2_marker_after_commit_boundary(&high_decision)
        .expect("persist higher-seq v2 marker");
    assert!(marker_path.exists());
    let marker_bytes_before = std::fs::read(&marker_path).unwrap();

    // Candidate at sequence 5 — strictly lower. decide_v2 must reject.
    let low_ratification = build_valid_v2_ratification(&h, 5);
    let low_ratified = ratified_v2(&h, &low_ratification);
    let err = decide_marker_acceptance_v2(build_marker_v2_inputs(
        &marker_path,
        &gh_hex,
        &low_ratification,
        &low_ratified,
    ))
    .expect_err("v2 rollback must reject");
    assert!(
        matches!(
            err,
            MutatingSurfaceMarkerV2Error::LowerV2SequenceRefused {
                persisted_sequence: 7,
                attempted_sequence: 5,
            }
        ),
        "got {:?}",
        err
    );

    // Orchestration contract: on Err from decide_v2, the binary MUST
    // skip the apply call entirely.
    let ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let log = ctx.log();
    drop(ctx);
    let events = log.lock().unwrap().events.clone();
    assert!(
        events.is_empty(),
        "Run 134 orchestration: v2 marker-reject must NOT invoke any apply callback"
    );

    let marker_bytes_after = std::fs::read(&marker_path).unwrap();
    assert_eq!(marker_bytes_before, marker_bytes_after);
    assert!(!seq_path.exists(), "sequence file must not be created on reject");
}

/// §C.3 — decide_v2 accepts but apply fails at swap; the v2 marker is
/// NOT persisted.
#[test]
fn run134_apply_failure_after_v2_accept_does_not_persist_marker() {
    let h = devnet_harness();
    let dir = tmpdir("applyerr");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    let bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "cand.json", &bundle);
    let ratification = build_valid_v2_ratification(&h, 5);
    let ratified = ratified_v2(&h, &ratification);
    let gh_hex = runtime_genesis_hash_hex(&h);

    assert!(!marker_path.exists());

    let decision = decide_marker_acceptance_v2(build_marker_v2_inputs(
        &marker_path,
        &gh_hex,
        &ratification,
        &ratified,
    ))
    .expect("v2 first-write accept");

    let mut ctx = FakeLiveTrustApplyContext::with_swap_failure("aaaaaaaa");
    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path));
    let apply_outcome = apply_validated_candidate_with_previous(
        inputs,
        ApplyMode::ApplyLive,
        Some(&mut ctx),
        "aaaaaaaa".to_string(),
        Some(1),
    );
    assert!(apply_outcome.is_err(), "apply must surface swap failure");

    // Orchestration contract: on Err, do NOT call persist.
    assert!(
        !marker_path.exists(),
        "v2 marker MUST NOT be persisted when apply pipeline returns Err"
    );
    drop(decision);
    assert!(!marker_path.exists());
}

/// §C.4 — re-apply of an identical v2 candidate produces an Idempotent
/// decision; persist is a strict no-op (file bytes unchanged).
#[test]
fn run134_idempotent_v2_re_apply_does_not_rewrite_marker() {
    let h = devnet_harness();
    let dir = tmpdir("idempotent");
    let seq_path = sequence_file_path(&dir);
    let marker_path = authority_state_file_path(&dir);
    let bundle = build_signed_bundle(&h, 2, 200);
    let candidate_path = write_bundle(&dir, "cand.json", &bundle);
    let ratification = build_valid_v2_ratification(&h, 5);
    let ratified = ratified_v2(&h, &ratification);
    let gh_hex = runtime_genesis_hash_hex(&h);

    // First apply — clean accept + persist.
    let d1 = decide_marker_acceptance_v2(build_marker_v2_inputs(
        &marker_path,
        &gh_hex,
        &ratification,
        &ratified,
    ))
    .expect("first-v2-write");
    let mut ctx1 = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let inputs1 = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path));
    apply_validated_candidate_with_previous(
        inputs1,
        ApplyMode::ApplyLive,
        Some(&mut ctx1),
        "aaaaaaaa".to_string(),
        Some(1),
    )
    .expect("first apply Ok");
    persist_accepted_v2_marker_after_commit_boundary(&d1).expect("first v2 persist Ok");
    let marker_bytes_after_first = std::fs::read(&marker_path).unwrap();

    // Second apply — identical inputs.
    let d2 = decide_marker_acceptance_v2(build_marker_v2_inputs(
        &marker_path,
        &gh_hex,
        &ratification,
        &ratified,
    ))
    .expect("second decide_v2");
    assert!(
        matches!(d2.kind(), MarkerAcceptKindV2::Idempotent),
        "expected Idempotent, got {:?}",
        d2.kind()
    );
    assert!(!d2.should_persist());

    let mut ctx2 = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let inputs2 = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path));
    let _ = apply_validated_candidate_with_previous(
        inputs2,
        ApplyMode::ApplyLive,
        Some(&mut ctx2),
        "aaaaaaaa".to_string(),
        Some(2),
    );

    persist_accepted_v2_marker_after_commit_boundary(&d2)
        .expect("idempotent v2 persist Ok (no-op)");
    let marker_bytes_after_second = std::fs::read(&marker_path).unwrap();
    assert_eq!(
        marker_bytes_after_first, marker_bytes_after_second,
        "idempotent v2 persist must NOT rewrite the marker file"
    );
}

/// §C.5 — a v2 candidate against a pre-persisted v1 marker is accepted
/// as an explicit v1 → v2 migration; the marker on disk is rewritten as
/// v2 after `commit_sequence`.
#[test]
fn run134_v2_after_v1_marker_migrates_to_v2_on_persist() {
    use qbind_node::pqc_authority_marker_acceptance::{
        decide_marker_acceptance, persist_accepted_marker_after_commit_boundary,
        MarkerAcceptanceInputs,
    };

    let h = devnet_harness();
    let dir = tmpdir("v2afterv1");
    let marker_path = authority_state_file_path(&dir);
    let gh_hex = runtime_genesis_hash_hex(&h);

    // Step A: pre-persist a v1 marker via the Run 119 helpers so the
    // on-disk record is a real v1 envelope (not a synthetic one).
    use qbind_ledger::{
        bundle_signing_ratification::test_helpers as v1_helpers,
        enforce_bundle_signing_key_ratification, RatificationEnforcementInputs,
        RatificationEnforcementOutcome, RatificationEnforcementPolicy,
    };
    let v1_ratification = v1_helpers::build_signed_ratification(
        &h.chain_id_str,
        RatificationEnvironment::Devnet,
        h.canonical_hash,
        &hex_lower(&h.authority_pk),
        &h.authority_sk,
        &h.signing_pk,
    );
    let v1_outcome = enforce_bundle_signing_key_ratification(RatificationEnforcementInputs {
        ratification: Some(&v1_ratification),
        authority: h.genesis_cfg.authority.as_ref().unwrap(),
        expected_chain_id: &h.chain_id_str,
        expected_environment: h.env_policy,
        expected_genesis_hash: &h.canonical_hash,
        candidate_bundle_signing_public_key: &h.signing_pk,
        policy: RatificationEnforcementPolicy::Strict,
    })
    .expect("Run 105 enforces clean v1 ratification");
    let v1_ratified = match v1_outcome {
        RatificationEnforcementOutcome::Ratified(rk) => rk,
        other => panic!("expected Ratified, got {:?}", other),
    };
    let authority = h.genesis_cfg.authority.as_ref().unwrap();
    let v1_decision = decide_marker_acceptance(MarkerAcceptanceInputs {
        marker_path: &marker_path,
        runtime_env: NetworkEnvironment::Devnet,
        runtime_chain_id: NetworkEnvironment::Devnet.chain_id(),
        runtime_genesis_hash_hex: &gh_hex,
        authority_policy_version: authority.authority_policy_version,
        authority_sequence: authority.authority_sequence,
        authority_epoch: authority.authority_epoch,
        ratification: &v1_ratification,
        ratified: &v1_ratified,
        update_source: AuthorityStateUpdateSource::ReloadApply,
        updated_at_unix_secs: 100,
    })
    .expect("v1 first-write");
    persist_accepted_marker_after_commit_boundary(&v1_decision).expect("v1 persist");

    // Confirm the on-disk marker is v1.
    match load_authority_state_versioned(&marker_path).unwrap() {
        Some(PersistentAuthorityStateRecordVersioned::V1(_)) => {}
        other => panic!("expected V1 on disk after step A, got {:?}", other),
    }

    // Step B: v2 candidate. decide_v2 must classify this as
    // V2AfterV1Migration and should_persist must be true.
    let v2_ratification = build_valid_v2_ratification(&h, 5);
    let v2_ratified = ratified_v2(&h, &v2_ratification);
    let v2_decision = decide_marker_acceptance_v2(build_marker_v2_inputs(
        &marker_path,
        &gh_hex,
        &v2_ratification,
        &v2_ratified,
    ))
    .expect("v2-after-v1 migration accept");
    assert!(matches!(
        v2_decision.kind(),
        MarkerAcceptKindV2::V2AfterV1Migration
    ));
    assert!(v2_decision.should_persist());

    // Step C: persist v2 marker after commit_sequence.
    persist_accepted_v2_marker_after_commit_boundary(&v2_decision)
        .expect("v2 persist after migration Ok");

    // On-disk marker is now v2.
    match load_authority_state_versioned(&marker_path).unwrap() {
        Some(PersistentAuthorityStateRecordVersioned::V2(v2)) => {
            assert_eq!(v2.latest_authority_domain_sequence, 5);
        }
        other => panic!("expected V2 on disk after migration, got {:?}", other),
    }
}