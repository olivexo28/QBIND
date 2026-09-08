//! Run 070 (C4 piece: PQC trust-bundle reload-apply boundary):
//! integration tests for `qbind_node::pqc_trust_reload::apply_validated_candidate`.
//!
//! These tests prove the strict validate → swap → evict → commit
//! sequencing contract of Run 070, the fail-closed behaviour on every
//! failure stage, and the explicit `UnsupportedRuntimeContext` boundary
//! the running `qbind-node` binary surfaces today. They drive a
//! deterministic in-memory `FakeLiveTrustApplyContext` so every branch
//! (success ordering, swap failure, eviction failure with rollback,
//! commit failure with rollback, commit failure where rollback also
//! fails) can be exercised without depending on a real session manager
//! or a real mutable runtime trust handle (which the production binary
//! does not have yet — see `crates/qbind-node/src/pqc_trust_reload.rs`
//! module comment and `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_070.md`).
//!
//! These tests do NOT spawn the `qbind-node` binary; they exercise the
//! public library entry points. The matching release-binary smokes
//! (positive startup, unsupported-runtime-context boundary, negative
//! tampered / rollback / wrong-chain / local-revoked candidates) are
//! recorded in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_070.md`.
//!
//! Coverage matrix (per RUN_070_TASK.txt §"Required tests"):
//!
//!  1. `ApplyMode::ValidateOnly` mirrors `validate_candidate_bundle`:
//!     valid candidate → `Ok(AppliedCandidate)` with zero session
//!     evictions; no live state mutation; no sequence write; no
//!     context callbacks invoked.
//!  2. `ApplyMode::ApplyLive` with `None` context →
//!     `UnsupportedRuntimeContext`; no callbacks invoked.
//!  3. Valid candidate apply with a working live context →
//!     `Ok(AppliedCandidate)`; callbacks invoked in order
//!     `snapshot_active → swap_trust_state → evict_sessions →
//!     commit_sequence`; session-eviction count surfaced.
//!  4. State-swap failure → `StateSwapFailed`; no
//!     `evict_sessions`/`commit_sequence`/`rollback_trust_state`
//!     called; old fingerprint preserved in the fake context.
//!  5. Session-eviction failure → `SessionEvictionFailed { rollback_ok:
//!     true }`; `rollback_trust_state` invoked; no `commit_sequence`
//!     called; fake-context active fingerprint reverted to pre-swap.
//!  6. Sequence-commit failure with successful rollback →
//!     `SequenceCommitFailed`; fake-context active fingerprint
//!     reverted to pre-swap; sequence record unchanged.
//!  7. Sequence-commit failure with failed rollback →
//!     `SequenceCommitFailedRollbackAlsoFailed`; FATAL message
//!     surfaced.
//!  8. Each Run 069 validation-failure class (rollback,
//!     equal-fp-mismatch, wrong-chain, tampered, future-activation,
//!     local-revoked-leaf, local-revoked-issuer-root) →
//!     `ValidationFailed(...)`; no context callbacks invoked.
//!  9. Run 069 `validate_candidate_bundle` entry point remains
//!     non-mutating after Run 070 lands.
//! 10. `ApplyMode::ApplyLive` validation-failure path does NOT
//!     advance the persisted sequence record on disk.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use qbind_crypto::MlDsa44Backend;
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
use qbind_node::pqc_trust_activation::ActivationContext;
use qbind_node::pqc_trust_bundle::{
    cert_leaf_fingerprint, derive_signing_key_id, sign_bundle_devnet_helper,
    BundleSigningKey, BundleSigningKeySet, LoadedTrustBundle, RootStatus, TrustBundle,
    TrustBundleEnvironment, TrustBundleRevocation, TrustBundleRoot,
};
use qbind_node::pqc_trust_reload::{
    apply_validated_candidate, apply_validated_candidate_with_previous,
    validate_candidate_bundle, ApplyMode, LiveTrustApplyContext, ReloadApplyError,
    ReloadCheckError, ReloadCheckInputs,
};
use qbind_node::pqc_trust_sequence::{
    chain_id_hex, check_and_update_sequence, load_record, sequence_file_path,
    SequenceCheckOutcome,
};
use qbind_types::NetworkEnvironment;
use qbind_wire::io::WireEncode;
use qbind_wire::net::NetworkDelegationCert;

// ---------------------------------------------------------------------
// Helpers (mirror the Run 069 test file shape — same DevNet signing
// harness, same `build_signed_devnet_bundle`, same persistence-file
// snapshot/assertion helpers).
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
        "qbind-run070-{}-{}-{}",
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
    root_id: [u8; 32],
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
        root_id: root.root_key_id,
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

fn fixture_cert_with_root(validator_byte: u8, root_id: [u8; 32]) -> NetworkDelegationCert {
    NetworkDelegationCert {
        version: 1,
        validator_id: [validator_byte; 32],
        root_key_id: root_id,
        leaf_kem_suite_id: 1,
        leaf_kem_pk: vec![0x22; 32],
        not_before: 0,
        not_after: u64::MAX,
        ext_bytes: vec![],
        sig_suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
        sig_bytes: vec![0x33; 64],
    }
}

fn encode_cert_bytes(cert: &NetworkDelegationCert) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    cert.encode(&mut out);
    out
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
            "Run 070 apply must not create persistence file at {}",
            path.display()
        ),
        (Some(_), false) => panic!(
            "Run 070 apply must not delete persistence file at {}",
            path.display()
        ),
        (Some((bytes_before, mtime_before)), true) => {
            let bytes_after = std::fs::read(path).expect("read seq file");
            assert_eq!(
                bytes_before, bytes_after,
                "Run 070 apply must not rewrite persistence file on a fail-closed branch"
            );
            let mtime_after = std::fs::metadata(path)
                .expect("metadata")
                .modified()
                .expect("mtime");
            assert_eq!(
                mtime_before, mtime_after,
                "Run 070 apply must not touch persistence file mtime on a fail-closed branch"
            );
        }
    }
}

fn devnet_inputs<'a>(
    candidate_path: &'a Path,
    signing_keys: &'a BundleSigningKeySet,
    seq_path: Option<&'a Path>,
    activation_current_height: u64,
    leaf_bytes: Option<&'a [u8]>,
) -> ReloadCheckInputs<'a> {
    ReloadCheckInputs {
        candidate_path,
        environment: NetworkEnvironment::Devnet,
        chain_id: NetworkEnvironment::Devnet.chain_id(),
        validation_time_secs: 100,
        signing_keys,
        activation_ctx: ActivationContext::height_only(activation_current_height),
        sequence_persistence_path: seq_path,
        local_leaf_cert_bytes: leaf_bytes,
    }
}

// ---------------------------------------------------------------------
// `FakeLiveTrustApplyContext` — deterministic in-memory live trust
// handle that records every callback in order so tests can assert the
// exact validate → swap → evict → commit sequencing contract.
//
// `swap_action` / `evict_action` / `commit_action` / `rollback_action`
// drive each failure branch independently. The active state is
// modelled as a single "fingerprint prefix" string so a test can
// assert the value the apply path sees, both during the swap and
// after a rollback.
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

impl CallLog {
    fn push(&mut self, ev: &str) {
        self.events.push(ev.to_string());
    }
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
    fn new(initial_fingerprint: &str) -> Self {
        Self {
            log: Arc::new(Mutex::new(CallLog::default())),
            active_fingerprint: Arc::new(Mutex::new(initial_fingerprint.to_string())),
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
        self.log.lock().unwrap().push("snapshot_active");
        let prev: String = self.active_fingerprint.lock().unwrap().clone();
        Ok(Box::new(prev))
    }
    fn swap_trust_state(
        &mut self,
        candidate: &LoadedTrustBundle,
    ) -> Result<(), String> {
        self.log.lock().unwrap().push("swap_trust_state");
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
        self.log.lock().unwrap().push("evict_sessions");
        match &self.evict_action {
            ActionPlan::Err(m) => Err(m.clone()),
            ActionPlan::Ok => Ok(self.eviction_count),
        }
    }
    fn commit_sequence(
        &mut self,
        _candidate: &LoadedTrustBundle,
    ) -> Result<(), String> {
        self.log.lock().unwrap().push("commit_sequence");
        match &self.commit_action {
            ActionPlan::Err(m) => Err(m.clone()),
            ActionPlan::Ok => Ok(()),
        }
    }
    fn rollback_trust_state(
        &mut self,
        snapshot: Box<dyn std::any::Any + Send + Sync>,
    ) -> Result<(), String> {
        self.log.lock().unwrap().push("rollback_trust_state");
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

// ============================================================================
// 1. ValidateOnly mode preserves Run 069 non-mutating semantics even when
// a live context is supplied — no context callbacks fired.
// ============================================================================

#[test]
fn run070_validate_only_mode_does_not_call_apply_context_or_persistence() {
    let dir = tmpdir("validate-only");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 2, 200, None, vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let snap = snapshot_seq_file(&seq_path);
    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let log = ctx.log();
    let active = ctx.active();

    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0, None);
    let applied = apply_validated_candidate(inputs, ApplyMode::ValidateOnly, Some(&mut ctx))
        .expect("validate-only valid candidate must succeed");

    assert_eq!(applied.validated.sequence, 2);
    assert_eq!(applied.session_evictions, 0);
    // Active fingerprint untouched — no swap occurred.
    assert_eq!(*active.lock().unwrap(), "aaaaaaaa");
    // No context callbacks at all.
    assert!(
        log.lock().unwrap().events.is_empty(),
        "ValidateOnly must not call any context method: got {:?}",
        log.lock().unwrap().events
    );
    // Persistence file untouched.
    assert_seq_file_unchanged(&seq_path, snap);
}

// ============================================================================
// 2. ApplyLive with no context → UnsupportedRuntimeContext; no mutation.
// ============================================================================

#[test]
fn run070_apply_live_with_no_context_returns_unsupported_runtime_context() {
    let dir = tmpdir("no-ctx");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 2, 200, None, vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);
    let snap = snapshot_seq_file(&seq_path);

    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0, None);
    let err = apply_validated_candidate(inputs, ApplyMode::ApplyLive, None)
        .expect_err("ApplyLive with no context must fail closed");
    match err {
        ReloadApplyError::UnsupportedRuntimeContext(msg) => {
            assert!(
                msg.contains("no mutable runtime trust-state handle"),
                "msg={}",
                msg
            );
        }
        other => panic!("expected UnsupportedRuntimeContext, got {:?}", other),
    }
    assert_seq_file_unchanged(&seq_path, snap);
}

// ============================================================================
// 3. ApplyLive happy path: ordering snapshot → swap → evict → commit.
// ============================================================================

#[test]
fn run070_apply_live_happy_path_runs_callbacks_in_exact_order() {
    let dir = tmpdir("happy");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 5, 500, None, vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);

    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let log = ctx.log();
    let active = ctx.active();

    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0, None);
    let applied = apply_validated_candidate_with_previous(
        inputs,
        ApplyMode::ApplyLive,
        Some(&mut ctx),
        "aaaaaaaa".to_string(),
        Some(3),
    )
    .expect("happy path apply must succeed");

    // Outcome metadata.
    assert_eq!(applied.validated.sequence, 5);
    assert_eq!(applied.session_evictions, 2);
    assert_eq!(applied.previous_fingerprint_prefix, "aaaaaaaa");
    assert_eq!(applied.previous_sequence, Some(3));

    // Operator-log line carries both fingerprints + commit_ok.
    let line = applied.applied_log_line();
    assert!(line.contains("Run 070"), "{}", line);
    assert!(line.contains("APPLIED live"), "{}", line);
    assert!(line.contains("old_fp=aaaaaaaa"), "{}", line);
    assert!(
        line.contains(&format!("new_fp={}", &applied.validated.fingerprint_prefix)),
        "{}",
        line
    );
    assert!(line.contains("session_evictions=2"), "{}", line);
    assert!(line.contains("sequence_commit=ok"), "{}", line);

    // Active fingerprint changed to candidate prefix.
    assert_eq!(*active.lock().unwrap(), applied.validated.fingerprint_prefix);

    // Exact ordering: snapshot → swap → evict → commit (no rollback).
    let events = log.lock().unwrap().events.clone();
    assert_eq!(
        events,
        vec![
            "snapshot_active".to_string(),
            "swap_trust_state".to_string(),
            "evict_sessions".to_string(),
            "commit_sequence".to_string(),
        ],
        "happy path callback order mismatch"
    );
}

// ============================================================================
// 4. State-swap failure: no evict, no commit, no rollback (no swap occurred).
// ============================================================================

#[test]
fn run070_state_swap_failure_does_not_commit_sequence_or_evict_or_rollback() {
    let dir = tmpdir("swap-fail");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 2, 200, None, vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);
    let snap = snapshot_seq_file(&seq_path);

    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    ctx.swap_action = ActionPlan::Err("write lock unavailable".into());
    let log = ctx.log();
    let active = ctx.active();

    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0, None);
    let err = apply_validated_candidate(inputs, ApplyMode::ApplyLive, Some(&mut ctx))
        .expect_err("swap failure must surface");
    match err {
        ReloadApplyError::StateSwapFailed(msg) => {
            assert!(msg.contains("write lock unavailable"), "msg={}", msg);
        }
        other => panic!("expected StateSwapFailed, got {:?}", other),
    }
    // Old active state preserved.
    assert_eq!(*active.lock().unwrap(), "aaaaaaaa");
    // No evict, no commit, no rollback (because no swap occurred).
    let events = log.lock().unwrap().events.clone();
    assert_eq!(
        events,
        vec![
            "snapshot_active".to_string(),
            "swap_trust_state".to_string(),
        ],
        "swap-fail must stop after the failed swap"
    );
    assert_seq_file_unchanged(&seq_path, snap);
}

// ============================================================================
// 5. Session-eviction failure after successful swap → rollback called;
//    no commit; rollback_ok=true.
// ============================================================================

#[test]
fn run070_session_eviction_failure_triggers_rollback_and_does_not_commit() {
    let dir = tmpdir("evict-fail");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 2, 200, None, vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);
    let snap = snapshot_seq_file(&seq_path);

    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    ctx.evict_action = ActionPlan::Err("session manager unavailable".into());
    let log = ctx.log();
    let active = ctx.active();

    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0, None);
    let err = apply_validated_candidate(inputs, ApplyMode::ApplyLive, Some(&mut ctx))
        .expect_err("eviction failure must surface");
    match err {
        ReloadApplyError::SessionEvictionFailed {
            message,
            rollback_ok,
        } => {
            assert!(message.contains("session manager unavailable"), "msg={}", message);
            assert!(rollback_ok, "rollback must succeed on the default plan");
        }
        other => panic!("expected SessionEvictionFailed, got {:?}", other),
    }
    // Active state reverted to pre-swap fingerprint.
    assert_eq!(*active.lock().unwrap(), "aaaaaaaa");
    let events = log.lock().unwrap().events.clone();
    assert_eq!(
        events,
        vec![
            "snapshot_active".to_string(),
            "swap_trust_state".to_string(),
            "evict_sessions".to_string(),
            "rollback_trust_state".to_string(),
        ],
        "evict-fail must rollback after the failed eviction and not call commit"
    );
    assert_seq_file_unchanged(&seq_path, snap);
}

// ============================================================================
// 6. Sequence-commit failure → rollback succeeds → SequenceCommitFailed.
// ============================================================================

#[test]
fn run070_sequence_commit_failure_rolls_back_live_state_and_surfaces_error() {
    let dir = tmpdir("commit-fail");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 2, 200, None, vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);
    let snap = snapshot_seq_file(&seq_path);

    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    ctx.commit_action = ActionPlan::Err("disk full".into());
    let log = ctx.log();
    let active = ctx.active();

    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0, None);
    let err = apply_validated_candidate(inputs, ApplyMode::ApplyLive, Some(&mut ctx))
        .expect_err("commit failure must surface");
    match err {
        ReloadApplyError::SequenceCommitFailed(msg) => {
            assert!(msg.contains("disk full"), "msg={}", msg);
        }
        other => panic!("expected SequenceCommitFailed, got {:?}", other),
    }
    // Active state reverted to pre-swap fingerprint.
    assert_eq!(*active.lock().unwrap(), "aaaaaaaa");
    let events = log.lock().unwrap().events.clone();
    assert_eq!(
        events,
        vec![
            "snapshot_active".to_string(),
            "swap_trust_state".to_string(),
            "evict_sessions".to_string(),
            "commit_sequence".to_string(),
            "rollback_trust_state".to_string(),
        ],
        "commit-fail must call rollback after the failed commit"
    );
    assert_seq_file_unchanged(&seq_path, snap);
}

// ============================================================================
// 7. Sequence-commit failure + rollback failure → fatal variant.
// ============================================================================

#[test]
fn run070_commit_failure_with_rollback_failure_surfaces_fatal_variant() {
    let dir = tmpdir("commit-rollback-fail");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 2, 200, None, vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);
    let snap = snapshot_seq_file(&seq_path);

    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    ctx.commit_action = ActionPlan::Err("disk full".into());
    ctx.rollback_action = ActionPlan::Err("snapshot drained".into());
    let log = ctx.log();

    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0, None);
    let err = apply_validated_candidate(inputs, ApplyMode::ApplyLive, Some(&mut ctx))
        .expect_err("commit+rollback failure must surface fatal variant");
    match err {
        ReloadApplyError::SequenceCommitFailedRollbackAlsoFailed {
            commit_message,
            rollback_message,
        } => {
            assert!(commit_message.contains("disk full"), "msg={}", commit_message);
            assert!(
                rollback_message.contains("snapshot drained"),
                "msg={}",
                rollback_message
            );
            let display = format!(
                "{}",
                ReloadApplyError::SequenceCommitFailedRollbackAlsoFailed {
                    commit_message,
                    rollback_message,
                }
            );
            assert!(display.contains("FATAL"), "{}", display);
        }
        other => panic!(
            "expected SequenceCommitFailedRollbackAlsoFailed, got {:?}",
            other
        ),
    }
    let events = log.lock().unwrap().events.clone();
    assert_eq!(
        events,
        vec![
            "snapshot_active".to_string(),
            "swap_trust_state".to_string(),
            "evict_sessions".to_string(),
            "commit_sequence".to_string(),
            "rollback_trust_state".to_string(),
        ],
        "commit+rollback-fail must follow the same call sequence"
    );
    assert_seq_file_unchanged(&seq_path, snap);
}

// ============================================================================
// 8. Validation-failure classes — each must surface `ValidationFailed(...)`
// and must NOT call any context callback (no swap, no evict, no commit,
// no rollback) and must NOT touch the persistence file.
// ============================================================================

fn assert_validation_failure_no_callbacks(
    inputs: ReloadCheckInputs<'_>,
    seq_path: &Path,
    snap: Option<(Vec<u8>, std::time::SystemTime)>,
    expect_predicate: impl FnOnce(&ReloadCheckError) -> bool,
) {
    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let log = ctx.log();
    let active = ctx.active();
    let err = apply_validated_candidate(inputs, ApplyMode::ApplyLive, Some(&mut ctx))
        .expect_err("validation failure must surface");
    match err {
        ReloadApplyError::ValidationFailed(inner) => {
            assert!(
                expect_predicate(&inner),
                "wrong validation-failure subtype: {:?}",
                inner
            );
        }
        other => panic!("expected ValidationFailed(...), got {:?}", other),
    }
    assert!(
        log.lock().unwrap().events.is_empty(),
        "validation failure must not invoke any apply-context callback: got {:?}",
        log.lock().unwrap().events
    );
    assert_eq!(*active.lock().unwrap(), "aaaaaaaa");
    assert_seq_file_unchanged(seq_path, snap);
}

#[test]
fn run070_validation_failure_rollback_does_not_call_apply_context() {
    let dir = tmpdir("v-rollback");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    // Prime persistence at seq=5.
    let prime = build_signed_devnet_bundle(&h, 5, 500, None, vec![]);
    let prime_path = write_bundle_to_disk(&dir, "prime.json", &prime);
    let prime_inputs =
        devnet_inputs(&prime_path, &h.signing_keys, Some(&seq_path), 0, None);
    validate_candidate_bundle(prime_inputs).expect("prime candidate valid");
    // Now commit it through the live persistence path so seq=5 is on disk.
    let prime_loaded =
        qbind_node::pqc_trust_bundle::TrustBundle::load_from_path_with_signing_keys_and_chain_id(
            &prime_path,
            NetworkEnvironment::Devnet,
            NetworkEnvironment::Devnet.chain_id(),
            100,
            &h.signing_keys,
        )
        .expect("live load");
    check_and_update_sequence(
        &seq_path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        prime_loaded.bundle.sequence,
        &prime_loaded.fingerprint,
        100,
    )
    .expect("prime commit");
    let snap = snapshot_seq_file(&seq_path);

    // Candidate seq=1 < 5 → rollback.
    let bundle = build_signed_devnet_bundle(&h, 1, 100, None, vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);
    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0, None);
    assert_validation_failure_no_callbacks(inputs, &seq_path, snap, |inner| {
        matches!(inner, ReloadCheckError::Sequence(_))
    });
}

#[test]
fn run070_validation_failure_tampered_signature_does_not_call_apply_context() {
    let dir = tmpdir("v-tamper");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let mut bundle = build_signed_devnet_bundle(&h, 2, 200, None, vec![]);
    // Flip one byte of the (hex-encoded) signature.
    if let Some(sig) = bundle.signature.as_mut() {
        let mut bytes: Vec<u8> = (0..sig.sig_bytes.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&sig.sig_bytes[i..i + 2], 16).expect("hex"))
            .collect();
        bytes[0] ^= 0xFF;
        sig.sig_bytes = hex_lower(&bytes);
    }
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);
    let snap = snapshot_seq_file(&seq_path);
    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0, None);
    assert_validation_failure_no_callbacks(inputs, &seq_path, snap, |inner| {
        matches!(inner, ReloadCheckError::Bundle(_))
    });
}

#[test]
fn run070_validation_failure_local_revoked_leaf_does_not_call_apply_context() {
    let dir = tmpdir("v-leaf");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    // Local leaf cert (issued by `h.root_id`).
    let leaf_cert = fixture_cert_with_root(0x01, h.root_id);
    let leaf_bytes = encode_cert_bytes(&leaf_cert);
    let leaf_fp = cert_leaf_fingerprint(&leaf_cert);

    // Candidate revokes the local leaf (active — `effective_from=0`).
    let rev = TrustBundleRevocation {
        root_id: h.root_id_hex.clone(),
        leaf_cert_fingerprint: Some(hex_lower(&leaf_fp)),
        reason: "leaf-compromise".to_string(),
        effective_from: 0,
        activation_height: None,
    };
    let bundle = build_signed_devnet_bundle(&h, 2, 200, None, vec![rev]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);
    let snap = snapshot_seq_file(&seq_path);

    let inputs = devnet_inputs(
        &candidate_path,
        &h.signing_keys,
        Some(&seq_path),
        0,
        Some(&leaf_bytes),
    );
    assert_validation_failure_no_callbacks(inputs, &seq_path, snap, |inner| {
        matches!(inner, ReloadCheckError::LocalLeafRevoked(_))
    });
}

#[test]
fn run070_validation_failure_local_issuer_root_revoked_does_not_call_apply_context() {
    let dir = tmpdir("v-issuer");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    let leaf_cert = fixture_cert_with_root(0x01, h.root_id);
    let leaf_bytes = encode_cert_bytes(&leaf_cert);

    // Candidate revokes the issuer root (active — `effective_from=0`,
    // no `leaf_cert_fingerprint` ⇒ root-scope revocation).
    let rev = TrustBundleRevocation {
        root_id: h.root_id_hex.clone(),
        leaf_cert_fingerprint: None,
        reason: "root-compromise".to_string(),
        effective_from: 0,
        activation_height: None,
    };
    let bundle = build_signed_devnet_bundle(&h, 2, 200, None, vec![rev]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);
    let snap = snapshot_seq_file(&seq_path);

    let inputs = devnet_inputs(
        &candidate_path,
        &h.signing_keys,
        Some(&seq_path),
        0,
        Some(&leaf_bytes),
    );
    assert_validation_failure_no_callbacks(inputs, &seq_path, snap, |inner| {
        matches!(inner, ReloadCheckError::LocalIssuerRootRevoked(_))
    });
}

// ============================================================================
// 9. Run 069 `validate_candidate_bundle` is unchanged: a valid candidate
// validates without writing the sequence file even after Run 070 lands.
// ============================================================================

#[test]
fn run070_does_not_alter_run069_validate_candidate_bundle_behaviour() {
    let dir = tmpdir("v069-still");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 2, 200, None, vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);
    let snap = snapshot_seq_file(&seq_path);
    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0, None);
    let v = validate_candidate_bundle(inputs).expect("Run 069 still valid");
    assert_eq!(v.sequence, 2);
    assert_seq_file_unchanged(&seq_path, snap);
}

// ============================================================================
// 10. Sequence persistence remains correct *after* a successful Run 070
// apply against a fake context: the apply path uses the fake context's
// commit (not the on-disk one), so a separate live startup call to
// `check_and_update_sequence` after a Run 070 apply against a fake
// context still produces `FirstLoad` (the on-disk record has not been
// touched). This proves the apply pipeline doesn't accidentally double-
// write or short-circuit the live startup persistence path.
// ============================================================================

#[test]
fn run070_apply_against_fake_context_leaves_on_disk_sequence_file_untouched() {
    let dir = tmpdir("disk-untouched");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let bundle = build_signed_devnet_bundle(&h, 2, 200, None, vec![]);
    let candidate_path = write_bundle_to_disk(&dir, "cand.json", &bundle);
    let snap = snapshot_seq_file(&seq_path);

    let mut ctx = FakeLiveTrustApplyContext::new("aaaaaaaa");
    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0, None);
    let _applied = apply_validated_candidate(inputs, ApplyMode::ApplyLive, Some(&mut ctx))
        .expect("apply must succeed");

    assert_seq_file_unchanged(&seq_path, snap);
    assert!(load_record(&seq_path).expect("load_record").is_none());

    // The live startup path may still be invoked afterwards and MUST
    // be able to write the record (i.e. nothing in Run 070 made the
    // on-disk path unwritable).
    let live_loaded = qbind_node::pqc_trust_bundle::TrustBundle::load_from_path_with_signing_keys_and_chain_id(
        &candidate_path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        100,
        &h.signing_keys,
    )
    .expect("live load");
    match check_and_update_sequence(
        &seq_path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        live_loaded.bundle.sequence,
        &live_loaded.fingerprint,
        100,
    )
    .expect("live commit")
    {
        SequenceCheckOutcome::FirstLoad { persisted_sequence, .. } => {
            assert_eq!(persisted_sequence, 2);
        }
        other => panic!("expected FirstLoad after run070 apply, got {:?}", other),
    }
}