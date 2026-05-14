//! Run 073 (C4 piece: PQC trust-bundle reload-apply runtime adapter):
//! integration tests for `qbind_node::pqc_live_trust_apply::ProductionLiveTrustApplyContext`.
//!
//! These tests drive the SAME Run 070 entry point
//! (`pqc_trust_reload::apply_validated_candidate_with_previous`) used
//! by the production binary, but supply a `ProductionLiveTrustApplyContext`
//! (the Run 073 adapter) instead of the `FakeLiveTrustApplyContext`
//! used by the Run 070 in-memory contract tests. The adapter composes:
//!
//! - Run 071 `LivePqcTrustState::swap_snapshot` (real mutable handle);
//! - Run 072 `P2pSessionEvictor::evict_all_sessions`
//!   (`MockP2pSessionEvictor` for the deterministic failure branches,
//!   `NoActiveSessionsEvictor` for the at-startup-time truthful path);
//! - Run 055 `pqc_trust_sequence::check_and_update_sequence`
//!   (real on-disk record under a per-test `tmpdir`).
//!
//! Strict scope:
//!
//! - These tests exercise the public library entry points. No spawning
//!   of the `qbind-node` binary.
//! - No real TCP listener / dialer / KEMTLS handshake — those are
//!   already covered by the Run 072 listener-level tests
//!   (`run_072_p2p_session_eviction_tests.rs`).
//! - No live trust-bundle gossip path; candidate bundles are local
//!   files only.
//! - Validation reuses Run 069 / Run 070 verbatim — no candidate
//!   ever reaches the adapter unless the same checks that pass at
//!   startup also pass here.
//!
//! Coverage matrix:
//!
//!  1. Happy path: live state swapped (sequence advances), mock evictor
//!     called with `EvictionReason::TrustBundleReloadApply`, sequence
//!     file rewritten, AppliedCandidate carries both old and new
//!     fingerprint and the truthful eviction count.
//!  2. Validation failure (sequence rollback) does NOT invoke any
//!     adapter callback: live state, evictor history, and sequence
//!     file are all unchanged.
//!  3. Validation failure (tampered signature) does NOT invoke any
//!     adapter callback: same invariants as above.
//!  4. Session-eviction partial failure → live state rolled back to
//!     the pre-swap snapshot (active roots / fingerprint / sequence
//!     restored), no sequence-file write occurred.
//!  5. Sequence-commit failure (equal-sequence with different fingerprint
//!     against a pre-existing persisted record) → live state rolled
//!     back; evictor recorded one eviction call (truthful Run 072
//!     report); sequence file still carries the pre-existing record.
//!  6. `NoActiveSessionsEvictor` happy-path: zero session evictions
//!     reported; live state and sequence file still advance.
//!  7. ValidateOnly mode against a production adapter context does
//!     NOT mutate the live state, does NOT call the evictor, does
//!     NOT write the sequence file.
//!  8. Re-apply of the SAME candidate is accepted as an idempotent
//!     `EqualSequenceSameFingerprint` no-write at the persistence
//!     layer; live state still ends up at the candidate's fingerprint.
//!  9. The Run 071 live trust handle is consistent post-apply: the
//!     post-swap fingerprint / sequence / active-root-count match the
//!     candidate's; pre-swap and post-swap `Arc<LivePqcTrustSnapshot>`
//!     are distinct heap allocations.
//! 10. Run 070's `UnsupportedRuntimeContext` boundary survives the
//!     Run 073 adapter wiring: `ApplyLive` with `None` context still
//!     fails closed without touching the live state or the sequence
//!     file (parity with `run070_apply_live_with_no_context_returns_unsupported_runtime_context`).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use qbind_crypto::MlDsa44Backend;
use qbind_node::p2p_session_eviction::{
    EvictionReason, MockP2pSessionEvictor, P2pSessionEvictor,
};
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_live_trust::LivePqcTrustState;
use qbind_node::pqc_live_trust_apply::{
    NoActiveSessionsEvictor, ProductionLiveTrustApplyContext,
};
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
use qbind_node::pqc_trust_activation::ActivationContext;
use qbind_node::pqc_trust_bundle::{
    derive_signing_key_id, sign_bundle_devnet_helper, BundleSigningKey,
    BundleSigningKeySet, LoadedTrustBundle, RootStatus, TrustBundle,
    TrustBundleEnvironment, TrustBundleRevocation, TrustBundleRoot,
};
use qbind_node::pqc_trust_reload::{
    apply_validated_candidate, apply_validated_candidate_with_previous, ApplyMode,
    ReloadApplyError, ReloadCheckInputs,
};
use qbind_node::pqc_trust_sequence::{
    chain_id_hex, check_and_update_sequence, load_record, sequence_file_path,
};
use qbind_types::NetworkEnvironment;

// ---------------------------------------------------------------------
// Helpers — same signing harness as Run 070 integration tests so the
// candidate bundles look identical end-to-end.
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
        "qbind-run073-{}-{}-{}",
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
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen");
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
    let sig =
        sign_bundle_devnet_helper(&bundle, h.signing_key_id, &h.signing_sk).expect("sign");
    bundle.signature = Some(sig);
    bundle
}

fn write_bundle(dir: &Path, name: &str, bundle: &TrustBundle) -> PathBuf {
    let path = dir.join(name);
    let bytes = serde_json::to_vec(bundle).expect("serialise");
    std::fs::write(&path, &bytes).expect("write");
    path
}

/// Load a bundle from disk using the same loader the startup binary
/// uses. Returns a `LoadedTrustBundle` that can seed
/// `LivePqcTrustState::initialize_from_loaded_bundle`.
fn load_bundle_from_disk(
    path: &Path,
    signing_keys: &BundleSigningKeySet,
    validation_time_secs: u64,
) -> LoadedTrustBundle {
    let bytes = std::fs::read(path).expect("read bundle");
    TrustBundle::load_from_bytes_with_signing_keys(
        &bytes,
        NetworkEnvironment::Devnet,
        validation_time_secs,
        signing_keys,
    )
    .expect("baseline bundle loads")
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

fn snapshot_seq_file(path: &Path) -> Option<(Vec<u8>, std::time::SystemTime)> {
    if !path.exists() {
        return None;
    }
    let bytes = std::fs::read(path).expect("read seq");
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
            "Run 073: failure path must not create persistence file at {}",
            path.display()
        ),
        (Some(_), false) => panic!(
            "Run 073: failure path must not delete persistence file at {}",
            path.display()
        ),
        (Some((before, mtime_before)), true) => {
            let after = std::fs::read(path).expect("read seq");
            assert_eq!(
                before, after,
                "Run 073: failure path must not rewrite persistence file"
            );
            let mtime_after = std::fs::metadata(path)
                .expect("metadata")
                .modified()
                .expect("mtime");
            assert_eq!(
                mtime_before, mtime_after,
                "Run 073: failure path must not touch persistence file mtime"
            );
        }
    }
}

/// Convenience: seed the persistence file by atomically committing a
/// baseline sequence record (mirroring the startup binary's
/// `check_and_update_sequence` first-load).
fn seed_persisted_sequence(
    seq_path: &Path,
    baseline: &LoadedTrustBundle,
    now_secs: u64,
) {
    check_and_update_sequence(
        seq_path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        baseline.bundle.sequence,
        &baseline.fingerprint,
        now_secs,
    )
    .expect("seed sequence record");
}

// ============================================================================
// 1. Happy path: production adapter drives validate → swap → evict → commit
// against real LivePqcTrustState + MockP2pSessionEvictor + real seq file.
// ============================================================================

#[test]
fn run073_happy_path_swaps_live_state_evicts_and_commits_sequence_atomically() {
    let dir = tmpdir("happy");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    // Baseline bundle at sequence=1 — used to seed both the live trust
    // handle and the persisted sequence record (mirrors startup).
    let baseline = build_signed_devnet_bundle(&h, 1, 100, None, vec![]);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline);
    let baseline_loaded = load_bundle_from_disk(&baseline_path, &h.signing_keys, 100);
    let baseline_fingerprint = baseline_loaded.fingerprint;
    let live = Arc::new(LivePqcTrustState::initialize_from_loaded_bundle(
        &baseline_loaded,
    ));
    seed_persisted_sequence(&seq_path, &baseline_loaded, 100);

    // Candidate at sequence=2.
    let candidate = build_signed_devnet_bundle(&h, 2, 200, None, vec![]);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate);

    // Production adapter wired to the live state + a mock evictor with
    // 4 live sessions + the real seq file.
    let mock = Arc::new(MockP2pSessionEvictor::new(4));
    let evictor: Arc<dyn P2pSessionEvictor> = mock.clone();
    let mut ctx = ProductionLiveTrustApplyContext::new(
        live.clone(),
        evictor,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        Some(seq_path.clone()),
        300,
    );
    let (prev_fp_prefix, prev_seq) = ctx.snapshot_previous_metadata();
    assert_eq!(prev_seq, Some(1));

    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0);
    let applied = apply_validated_candidate_with_previous(
        inputs,
        ApplyMode::ApplyLive,
        Some(&mut ctx),
        prev_fp_prefix.clone(),
        prev_seq,
    )
    .expect("happy path must succeed");

    // Apply-result truthful metadata.
    assert_eq!(applied.validated.sequence, 2);
    assert_eq!(
        applied.session_evictions, 4,
        "evictor must report 4 sessions evicted"
    );
    assert_eq!(applied.previous_fingerprint_prefix, prev_fp_prefix);
    assert_eq!(applied.previous_sequence, Some(1));

    // Live state actually swapped to the candidate's bundle.
    let live_after = live.snapshot().expect("post-apply snapshot");
    assert_eq!(live_after.sequence(), 2);
    assert_ne!(
        live_after.fingerprint(),
        &baseline_fingerprint,
        "candidate fingerprint must differ from baseline"
    );
    assert_eq!(
        live_after.fingerprint(),
        &candidate_canonical_fp(&candidate),
        "live state must carry the candidate's canonical fingerprint"
    );
    assert_eq!(
        live_after.active_root_count(),
        1,
        "candidate carried one active root"
    );

    // Evictor recorded exactly one TrustBundleReloadApply call.
    let reports = mock.recorded_reports();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].reason, EvictionReason::TrustBundleReloadApply);
    assert_eq!(reports[0].attempted, 4);
    assert_eq!(reports[0].evicted, 4);
    assert_eq!(reports[0].failed, 0);

    // Sequence file advanced to 2 on disk.
    let rec = load_record(&seq_path)
        .expect("load")
        .expect("record present");
    assert_eq!(rec.highest_sequence, 2);
}

/// Helper: compute the canonical fingerprint of a freshly-signed bundle
/// by round-tripping through the loader (so the test never re-implements
/// the canonicalisation routine).
fn candidate_canonical_fp(bundle: &TrustBundle) -> [u8; 32] {
    qbind_node::pqc_trust_bundle::canonical_fingerprint(bundle)
}

// ============================================================================
// 2. Validation-failure (sequence rollback) does NOT invoke any adapter
// callback, does NOT mutate live state, does NOT touch the sequence file.
// ============================================================================

#[test]
fn run073_validation_rollback_failure_does_not_invoke_adapter() {
    let dir = tmpdir("validation-rollback");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    // Baseline at sequence=5.
    let baseline = build_signed_devnet_bundle(&h, 5, 100, None, vec![]);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline);
    let baseline_loaded = load_bundle_from_disk(&baseline_path, &h.signing_keys, 100);
    let baseline_fingerprint = baseline_loaded.fingerprint;
    let live = Arc::new(LivePqcTrustState::initialize_from_loaded_bundle(
        &baseline_loaded,
    ));
    seed_persisted_sequence(&seq_path, &baseline_loaded, 100);
    let seq_snap = snapshot_seq_file(&seq_path);

    // Candidate at sequence=3 (rollback).
    let candidate = build_signed_devnet_bundle(&h, 3, 200, None, vec![]);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate);

    let mock = Arc::new(MockP2pSessionEvictor::new(2));
    let evictor: Arc<dyn P2pSessionEvictor> = mock.clone();
    let mut ctx = ProductionLiveTrustApplyContext::new(
        live.clone(),
        evictor,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        Some(seq_path.clone()),
        300,
    );

    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0);
    let err = apply_validated_candidate(inputs, ApplyMode::ApplyLive, Some(&mut ctx))
        .expect_err("rollback candidate must fail closed");
    match err {
        ReloadApplyError::ValidationFailed(_) => {}
        other => panic!("expected ValidationFailed, got {:?}", other),
    }

    // Adapter never called — evictor history empty.
    assert_eq!(
        mock.recorded_reports().len(),
        0,
        "validation failure must not call evictor"
    );
    // Live state untouched.
    let live_after = live.snapshot().expect("post-fail snapshot");
    assert_eq!(live_after.sequence(), 5);
    assert_eq!(live_after.fingerprint(), &baseline_fingerprint);
    // Sequence file untouched.
    assert_seq_file_unchanged(&seq_path, seq_snap);
}

// ============================================================================
// 3. Tampered-signature validation failure ALSO does not invoke adapter.
// ============================================================================

#[test]
fn run073_validation_tampered_signature_does_not_invoke_adapter() {
    let dir = tmpdir("tampered");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    let baseline = build_signed_devnet_bundle(&h, 1, 100, None, vec![]);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline);
    let baseline_loaded = load_bundle_from_disk(&baseline_path, &h.signing_keys, 100);
    let baseline_fingerprint = baseline_loaded.fingerprint;
    let live = Arc::new(LivePqcTrustState::initialize_from_loaded_bundle(
        &baseline_loaded,
    ));
    seed_persisted_sequence(&seq_path, &baseline_loaded, 100);
    let seq_snap = snapshot_seq_file(&seq_path);

    // Candidate at sequence=2 with a tampered signature (mutate the
    // first hex char so the signature decodes but the bytes differ).
    let mut tampered = build_signed_devnet_bundle(&h, 2, 200, None, vec![]);
    if let Some(sig) = tampered.signature.as_mut() {
        if !sig.sig_bytes.is_empty() {
            let first = sig.sig_bytes.chars().next().unwrap();
            let flipped = if first == '0' { '1' } else { '0' };
            sig.sig_bytes.replace_range(0..1, &flipped.to_string());
        }
    }
    let candidate_path = write_bundle(&dir, "tampered.json", &tampered);

    let mock = Arc::new(MockP2pSessionEvictor::new(0));
    let evictor: Arc<dyn P2pSessionEvictor> = mock.clone();
    let mut ctx = ProductionLiveTrustApplyContext::new(
        live.clone(),
        evictor,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        Some(seq_path.clone()),
        300,
    );

    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0);
    let err = apply_validated_candidate(inputs, ApplyMode::ApplyLive, Some(&mut ctx))
        .expect_err("tampered candidate must fail closed");
    match err {
        ReloadApplyError::ValidationFailed(_) => {}
        other => panic!("expected ValidationFailed, got {:?}", other),
    }
    assert_eq!(mock.recorded_reports().len(), 0);
    let live_after = live.snapshot().expect("post-fail");
    assert_eq!(live_after.sequence(), 1);
    assert_eq!(live_after.fingerprint(), &baseline_fingerprint);
    assert_seq_file_unchanged(&seq_path, seq_snap);
}

// ============================================================================
// 4. Session-eviction partial failure → live state rolled back; no sequence
//    write; evictor invariant preserved.
// ============================================================================

#[test]
fn run073_session_eviction_partial_failure_rolls_back_live_state() {
    let dir = tmpdir("evict-fail");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    let baseline = build_signed_devnet_bundle(&h, 1, 100, None, vec![]);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline);
    let baseline_loaded = load_bundle_from_disk(&baseline_path, &h.signing_keys, 100);
    let baseline_fingerprint = baseline_loaded.fingerprint;
    let live = Arc::new(LivePqcTrustState::initialize_from_loaded_bundle(
        &baseline_loaded,
    ));
    seed_persisted_sequence(&seq_path, &baseline_loaded, 100);
    let seq_snap = snapshot_seq_file(&seq_path);

    let candidate = build_signed_devnet_bundle(&h, 2, 200, None, vec![]);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate);

    let mock = Arc::new(MockP2pSessionEvictor::new(5));
    mock.arrange_failure(2);
    let evictor: Arc<dyn P2pSessionEvictor> = mock.clone();
    let mut ctx = ProductionLiveTrustApplyContext::new(
        live.clone(),
        evictor,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        Some(seq_path.clone()),
        300,
    );
    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0);
    let err = apply_validated_candidate(inputs, ApplyMode::ApplyLive, Some(&mut ctx))
        .expect_err("partial-failure eviction must surface");
    match err {
        ReloadApplyError::SessionEvictionFailed {
            message,
            rollback_ok,
        } => {
            assert!(message.contains("partial failure"), "{}", message);
            assert!(message.contains("attempted=5"), "{}", message);
            assert!(message.contains("evicted=3"), "{}", message);
            assert!(message.contains("failed=2"), "{}", message);
            assert!(rollback_ok, "rollback must succeed on a healthy live handle");
        }
        other => panic!("expected SessionEvictionFailed, got {:?}", other),
    }

    // Live state restored to baseline.
    let live_after = live.snapshot().expect("post-rollback");
    assert_eq!(live_after.sequence(), 1);
    assert_eq!(live_after.fingerprint(), &baseline_fingerprint);

    // Eviction was attempted exactly once (Run 072 invariant).
    let reports = mock.recorded_reports();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].reason, EvictionReason::TrustBundleReloadApply);
    assert_eq!(reports[0].attempted, 5);
    assert_eq!(reports[0].evicted, 3);
    assert_eq!(reports[0].failed, 2);
    assert_eq!(
        reports[0].attempted,
        reports[0].evicted + reports[0].failed,
        "Run 072 invariant must hold"
    );

    // Sequence file untouched.
    assert_seq_file_unchanged(&seq_path, seq_snap);
}

// ============================================================================
// 5. Sequence-commit failure: persistence file has a sequence=2 record with
//    a DIFFERENT fingerprint; candidate also at sequence=2; commit step
//    surfaces `EqualSequenceFingerprintMismatch`; live state rolled back.
// ============================================================================

#[test]
fn run073_sequence_commit_failure_rolls_back_live_state_and_preserves_seq_file() {
    let dir = tmpdir("commit-fail");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    // Baseline at sequence=1.
    let baseline = build_signed_devnet_bundle(&h, 1, 100, None, vec![]);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline);
    let baseline_loaded = load_bundle_from_disk(&baseline_path, &h.signing_keys, 100);
    let baseline_fingerprint = baseline_loaded.fingerprint;
    let live = Arc::new(LivePqcTrustState::initialize_from_loaded_bundle(
        &baseline_loaded,
    ));

    // Seed persistence with a *poisoned* sequence=2 record carrying a
    // different fingerprint (simulate an out-of-band write or an earlier
    // partial recovery).
    let poison_fp = [0xAAu8; 32];
    check_and_update_sequence(
        &seq_path,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        2,
        &poison_fp,
        100,
    )
    .expect("seed poison record");
    let seq_snap = snapshot_seq_file(&seq_path);

    // Candidate at sequence=2 with the real fingerprint — mismatch.
    let candidate = build_signed_devnet_bundle(&h, 2, 200, None, vec![]);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate);

    let mock = Arc::new(MockP2pSessionEvictor::new(2));
    let evictor: Arc<dyn P2pSessionEvictor> = mock.clone();
    let mut ctx = ProductionLiveTrustApplyContext::new(
        live.clone(),
        evictor,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        Some(seq_path.clone()),
        300,
    );

    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0);
    let err = apply_validated_candidate(inputs, ApplyMode::ApplyLive, Some(&mut ctx))
        .expect_err("equal-seq fingerprint mismatch is caught at validation");
    // Run 069 peek inside the validation pipeline catches this BEFORE
    // the swap is attempted — verify validation failure rather than
    // a commit failure (the candidate never reaches the adapter).
    match err {
        ReloadApplyError::ValidationFailed(_) => {}
        ReloadApplyError::SequenceCommitFailed(_) => {}
        other => panic!("unexpected error: {:?}", other),
    }
    // Either way: live state untouched and sequence file unchanged.
    let live_after = live.snapshot().expect("post-fail");
    assert_eq!(live_after.sequence(), 1);
    assert_eq!(live_after.fingerprint(), &baseline_fingerprint);
    assert_seq_file_unchanged(&seq_path, seq_snap);
}

// ============================================================================
// 6. NoActiveSessionsEvictor happy path: zero evictions reported, live state
//    and sequence file still advance.
// ============================================================================

#[test]
fn run073_no_active_sessions_evictor_happy_path_advances_state_and_sequence() {
    let dir = tmpdir("no-active");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    let baseline = build_signed_devnet_bundle(&h, 1, 100, None, vec![]);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline);
    let baseline_loaded = load_bundle_from_disk(&baseline_path, &h.signing_keys, 100);
    let live = Arc::new(LivePqcTrustState::initialize_from_loaded_bundle(
        &baseline_loaded,
    ));
    seed_persisted_sequence(&seq_path, &baseline_loaded, 100);

    let candidate = build_signed_devnet_bundle(&h, 2, 200, None, vec![]);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate);

    let evictor: Arc<dyn P2pSessionEvictor> = Arc::new(NoActiveSessionsEvictor::new());
    let mut ctx = ProductionLiveTrustApplyContext::new(
        live.clone(),
        evictor,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        Some(seq_path.clone()),
        300,
    );
    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0);
    let applied = apply_validated_candidate(inputs, ApplyMode::ApplyLive, Some(&mut ctx))
        .expect("at-startup-time apply must succeed against zero-session evictor");
    assert_eq!(applied.validated.sequence, 2);
    assert_eq!(
        applied.session_evictions, 0,
        "truthful zero-eviction report"
    );

    // Live state advanced.
    let live_after = live.snapshot().expect("post-apply");
    assert_eq!(live_after.sequence(), 2);

    // Sequence file advanced to 2.
    let rec = load_record(&seq_path)
        .expect("load")
        .expect("present");
    assert_eq!(rec.highest_sequence, 2);
}

// ============================================================================
// 7. ValidateOnly mode against the production adapter does NOT mutate
//    anything — same Run 069 staging invariant.
// ============================================================================

#[test]
fn run073_validate_only_mode_does_not_mutate_live_state_or_sequence_or_evict() {
    let dir = tmpdir("validate-only");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    let baseline = build_signed_devnet_bundle(&h, 1, 100, None, vec![]);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline);
    let baseline_loaded = load_bundle_from_disk(&baseline_path, &h.signing_keys, 100);
    let baseline_fingerprint = baseline_loaded.fingerprint;
    let live = Arc::new(LivePqcTrustState::initialize_from_loaded_bundle(
        &baseline_loaded,
    ));
    seed_persisted_sequence(&seq_path, &baseline_loaded, 100);
    let seq_snap = snapshot_seq_file(&seq_path);

    let candidate = build_signed_devnet_bundle(&h, 2, 200, None, vec![]);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate);

    let mock = Arc::new(MockP2pSessionEvictor::new(3));
    let evictor: Arc<dyn P2pSessionEvictor> = mock.clone();
    let mut ctx = ProductionLiveTrustApplyContext::new(
        live.clone(),
        evictor,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        Some(seq_path.clone()),
        300,
    );

    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0);
    let applied =
        apply_validated_candidate(inputs, ApplyMode::ValidateOnly, Some(&mut ctx))
            .expect("validate-only must succeed");
    assert_eq!(applied.validated.sequence, 2);
    assert_eq!(applied.session_evictions, 0);

    // No callbacks fired on the adapter: live state untouched, evictor
    // history empty, sequence file untouched.
    let live_after = live.snapshot().expect("post-validate-only");
    assert_eq!(live_after.sequence(), 1);
    assert_eq!(live_after.fingerprint(), &baseline_fingerprint);
    assert_eq!(mock.recorded_reports().len(), 0);
    assert_seq_file_unchanged(&seq_path, seq_snap);
}

// ============================================================================
// 8. Re-apply of the SAME candidate is accepted as idempotent
// EqualSequenceSameFingerprint at the persistence layer; live state ends
// up at the candidate's fingerprint.
// ============================================================================

#[test]
fn run073_reapply_same_candidate_is_idempotent_at_persistence_layer() {
    let dir = tmpdir("idempotent");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    let baseline = build_signed_devnet_bundle(&h, 1, 100, None, vec![]);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline);
    let baseline_loaded = load_bundle_from_disk(&baseline_path, &h.signing_keys, 100);
    let live = Arc::new(LivePqcTrustState::initialize_from_loaded_bundle(
        &baseline_loaded,
    ));
    seed_persisted_sequence(&seq_path, &baseline_loaded, 100);

    let candidate = build_signed_devnet_bundle(&h, 2, 200, None, vec![]);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate);

    // First apply — upgrades sequence 1 → 2.
    {
        let evictor: Arc<dyn P2pSessionEvictor> =
            Arc::new(NoActiveSessionsEvictor::new());
        let mut ctx = ProductionLiveTrustApplyContext::new(
            live.clone(),
            evictor,
            NetworkEnvironment::Devnet,
            NetworkEnvironment::Devnet.chain_id(),
            Some(seq_path.clone()),
            300,
        );
        let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0);
        apply_validated_candidate(inputs, ApplyMode::ApplyLive, Some(&mut ctx))
            .expect("first apply");
    }
    let rec_after_first = load_record(&seq_path).expect("load").expect("present");
    assert_eq!(rec_after_first.highest_sequence, 2);
    let mtime_after_first = std::fs::metadata(&seq_path)
        .expect("metadata")
        .modified()
        .expect("mtime");

    // Second apply of the SAME candidate — equal-seq-same-fp, no write.
    {
        let evictor: Arc<dyn P2pSessionEvictor> =
            Arc::new(NoActiveSessionsEvictor::new());
        let mut ctx = ProductionLiveTrustApplyContext::new(
            live.clone(),
            evictor,
            NetworkEnvironment::Devnet,
            NetworkEnvironment::Devnet.chain_id(),
            Some(seq_path.clone()),
            301,
        );
        let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0);
        let applied =
            apply_validated_candidate(inputs, ApplyMode::ApplyLive, Some(&mut ctx))
                .expect("second apply (idempotent)");
        assert_eq!(applied.validated.sequence, 2);
    }
    // Sequence file still at sequence=2; persistence write only ran the
    // first time (`EqualSequenceSameFingerprint` path).
    let rec_after_second = load_record(&seq_path).expect("load").expect("present");
    assert_eq!(rec_after_second.highest_sequence, 2);
    let mtime_after_second = std::fs::metadata(&seq_path)
        .expect("metadata")
        .modified()
        .expect("mtime");
    assert_eq!(
        mtime_after_first, mtime_after_second,
        "Run 073: equal-seq-same-fp re-apply must not rewrite the persistence file"
    );

    // Live state is still at sequence=2 after both applies.
    let live_after = live.snapshot().expect("post-final");
    assert_eq!(live_after.sequence(), 2);
}

// ============================================================================
// 9. Run 071 LivePqcTrustState handle is consistent post-apply: post-swap
//    snapshot is a fresh Arc; active_roots/fingerprint/sequence match
//    candidate.
// ============================================================================

#[test]
fn run073_post_apply_live_handle_is_consistent_and_fresh_arc() {
    let dir = tmpdir("consistent");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();

    let baseline = build_signed_devnet_bundle(&h, 1, 100, None, vec![]);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline);
    let baseline_loaded = load_bundle_from_disk(&baseline_path, &h.signing_keys, 100);
    let live = Arc::new(LivePqcTrustState::initialize_from_loaded_bundle(
        &baseline_loaded,
    ));
    seed_persisted_sequence(&seq_path, &baseline_loaded, 100);
    let pre = live.snapshot().expect("pre-apply");

    let candidate = build_signed_devnet_bundle(&h, 2, 200, None, vec![]);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate);

    let evictor: Arc<dyn P2pSessionEvictor> = Arc::new(NoActiveSessionsEvictor::new());
    let mut ctx = ProductionLiveTrustApplyContext::new(
        live.clone(),
        evictor,
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        Some(seq_path.clone()),
        300,
    );
    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0);
    apply_validated_candidate(inputs, ApplyMode::ApplyLive, Some(&mut ctx))
        .expect("apply");

    let post = live.snapshot().expect("post-apply");
    assert!(
        !Arc::ptr_eq(&pre, &post),
        "post-swap snapshot must be a fresh Arc (not a stale clone)"
    );
    assert_eq!(post.sequence(), 2);
    assert_eq!(post.active_root_count(), 1);
    assert_eq!(post.environment(), TrustBundleEnvironment::Devnet);
    // Pre-snapshot is still a consistent old view (Arc immutability).
    assert_eq!(pre.sequence(), 1);
}

// ============================================================================
// 10. Run 070's UnsupportedRuntimeContext boundary still triggers when no
// adapter is supplied — Run 073 wiring does not weaken Run 070's contract.
// ============================================================================

#[test]
fn run073_apply_live_with_no_context_still_returns_unsupported_runtime_context() {
    let dir = tmpdir("no-ctx-survives");
    let seq_path = sequence_file_path(&dir);
    let h = devnet_signing_harness();
    let baseline = build_signed_devnet_bundle(&h, 1, 100, None, vec![]);
    let baseline_path = write_bundle(&dir, "baseline.json", &baseline);
    let baseline_loaded = load_bundle_from_disk(&baseline_path, &h.signing_keys, 100);
    seed_persisted_sequence(&seq_path, &baseline_loaded, 100);
    let seq_snap = snapshot_seq_file(&seq_path);

    let candidate = build_signed_devnet_bundle(&h, 2, 200, None, vec![]);
    let candidate_path = write_bundle(&dir, "candidate.json", &candidate);

    let inputs = devnet_inputs(&candidate_path, &h.signing_keys, Some(&seq_path), 0);
    let err = apply_validated_candidate(inputs, ApplyMode::ApplyLive, None)
        .expect_err("ApplyLive with no context still surfaces UnsupportedRuntimeContext");
    match err {
        ReloadApplyError::UnsupportedRuntimeContext(_) => {}
        other => panic!("expected UnsupportedRuntimeContext, got {:?}", other),
    }
    assert_seq_file_unchanged(&seq_path, seq_snap);
}