//! Run 291 — source/test **production durable replay RocksDB backend** tests.
//!
//! Source/test only. Run 291 captures **no** release-binary evidence;
//! release-binary evidence is deferred to **Run 292**. These tests drive the
//! real RocksDB-backed [`ProductionDurableReplayRocksDbBackend`] against
//! temp-dir databases and prove:
//!
//! * A — open / schema: empty init, reopen same domain, wrong environment /
//!   chain / genesis / namespace / authority-domain-sequence, unsupported /
//!   malformed schema marker, missing / corrupted metadata, lock contention,
//!   unwritable path, disabled policy, MainNet refusal.
//! * B — write / read durability: write+read back, survive reopen, deterministic
//!   scan order, not-found without mutation, flush/reopen.
//! * C — idempotency / equivocation: duplicate idempotent (pre/post reopen),
//!   same id different digest / payload fails closed and preserves the original.
//! * D — atomicity / recovery: simulated pre-commit failure leaves no record,
//!   simulated partial-stage residue fails closed on reopen and recovers
//!   deterministically, corrupted payload / digest / truncated record fail
//!   closed.
//! * E — composition with the Run 238 fixture durable replay stack.
//! * F — security invariants (no fallback, default disabled, MainNet refused).
//! * G — C4/C5 taxonomy grep checks.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_291.md`.

use qbind_node::pqc_authority_lifecycle::LocalLifecycleAction;
use qbind_node::pqc_governance_authority::GovernanceAuthorityClass;
use qbind_node::pqc_governance_evaluator_replay_durable_backend::{
    durable_backend_key_digest, DurableBackendDecisionInput,
};
use qbind_node::pqc_governance_evaluator_replay_state::{
    EvaluatorReplayFreshnessInput, PreviouslySeenState,
};
use qbind_node::pqc_governance_execution_evaluator::{
    DecisionSourceIdentity, EvaluatorRequest, EvaluatorResponse, EvaluatorSourceKind,
    EVALUATOR_SUPPORTED_VERSION,
};
use qbind_node::pqc_governance_execution_policy::{
    GovernanceAction, GovernanceExecutionClass, GovernanceQuorumThreshold,
};
use qbind_node::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface;
use qbind_node::pqc_governance_production_durable_replay_rocksdb::{
    durable_replay_rocksdb_default_is_disabled,
    durable_replay_rocksdb_is_source_test_not_release_binary_evidence,
    durable_replay_rocksdb_mainnet_remains_refused,
    durable_replay_rocksdb_never_falls_back_to_in_memory, durable_replay_rocksdb_record_key,
    DurableReplayEventInput, DurableReplayRecordStage, DurableReplayRocksDbConfig,
    DurableReplayRocksDbError, DurableReplayRocksDbIdentity, DurableReplayRocksDbOpenOutcome,
    DurableReplayRocksDbPolicy, DurableReplayRocksDbReadOutcome, DurableReplayRocksDbRecoveryOutcome, GovernanceProductionDurableReplayBackend,
    MockDurableReplayBackend, ProductionDurableReplayRocksDbBackend, KEY_DOMAIN, KEY_SCHEMA,
    DURABLE_REPLAY_ROCKSDB_SCHEMA_VERSION,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;
use tempfile::TempDir;

// ===========================================================================
// Shared constants / builders (mirror the Run 238 corpus).
// ===========================================================================

const ROOT_FP: &str = "rootrootrootrootrootrootrootrootrootroot";
const CAND_DIGEST: &str = "candidate-digest-aaaaaaaaaaaaaaaaaaaaaaaa";
const GOV_PROOF: &str = "governance-proof-digest-bbbbbbbbbbbbbbbb";
const NONCE: &str = "replay-nonce-cccccccccccccccccccccccccc";
const PROPOSAL: &str = "proposal-0001";
const DECISION: &str = "decision-0001";
const CHAIN: &str = "qbind-devnet";
const GENESIS: &str = "genesis-hash-dddddddddddddddddddddddddddd";
const SOURCE_ID: &str = "decision-source-0001";
const DECISION_DIGEST: &str = "governance-execution-decision-digest-gggg";
const TRANSCRIPT_DIGEST: &str = "evaluator-transcript-digest-iiiiiiiiiiii";
const COMMIT: &str = "response-commitment-eeeeeeeeeeeeeeeeeeee";
const SEQUENCE: u64 = 7;

fn ev_identity(env: TrustBundleEnvironment, chain: &str, genesis: &str) -> DecisionSourceIdentity {
    DecisionSourceIdentity {
        evaluator_version: EVALUATOR_SUPPORTED_VERSION,
        source_kind: EvaluatorSourceKind::FixtureDecisionSource,
        source_id: SOURCE_ID.to_string(),
        governance_class: GovernanceExecutionClass::FixtureGovernance,
        issuer_authority_class: GovernanceAuthorityClass::GenesisBound,
        environment: env,
        chain_id: chain.to_string(),
        genesis_hash: genesis.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        governance_proof_digest: GOV_PROOF.to_string(),
        on_chain_proof_digest: None,
        custody_attestation_digest: None,
        freshness_replay_window: 200,
    }
}

fn ev_request(identity: &DecisionSourceIdentity, seq: u64) -> EvaluatorRequest {
    EvaluatorRequest {
        evaluator_version: EVALUATOR_SUPPORTED_VERSION,
        governance_execution_input_digest: "governance-execution-input-digest-jjjj".to_string(),
        proposal_id: PROPOSAL.to_string(),
        decision_id: DECISION.to_string(),
        governance_action: GovernanceAction::Rotate,
        lifecycle_action: LocalLifecycleAction::Rotate,
        candidate_digest: CAND_DIGEST.to_string(),
        authority_domain_sequence: seq,
        effective_epoch: 100,
        expiry_epoch: 200,
        replay_nonce: NONCE.to_string(),
        quorum: GovernanceQuorumThreshold::new(3, 5, 3),
        emergency_flag: false,
        decision_source_identity_digest: identity.source_identity_digest(),
    }
}

fn ev_response(request: &EvaluatorRequest, seq: u64) -> EvaluatorResponse {
    EvaluatorResponse {
        evaluator_version: EVALUATOR_SUPPORTED_VERSION,
        request_digest: request.request_digest(),
        decision_digest: DECISION_DIGEST.to_string(),
        approved: true,
        authorized_governance_action: GovernanceAction::Rotate,
        authorized_lifecycle_action: LocalLifecycleAction::Rotate,
        authorized_candidate_digest: CAND_DIGEST.to_string(),
        authorized_authority_domain_sequence: seq,
        effective_epoch: 100,
        expiry_epoch: 200,
        replay_nonce: NONCE.to_string(),
        evaluator_source_id: SOURCE_ID.to_string(),
        response_effective_epoch: 100,
        response_expiry_epoch: 200,
        emergency_flag: false,
        response_commitment: COMMIT.to_string(),
    }
}

/// Build a Run 238 durable decision input parameterized by env / chain /
/// genesis / sequence / nonce so distinct records can be produced.
fn decision_input(
    env: TrustBundleEnvironment,
    chain: &str,
    genesis: &str,
    seq: u64,
    decision_id: &str,
) -> DurableBackendDecisionInput {
    let identity = ev_identity(env, chain, genesis);
    let request = ev_request(&identity, seq);
    let response = ev_response(&request, seq);
    let freshness = EvaluatorReplayFreshnessInput::from_evaluator_material(
        &identity,
        &request,
        &response,
        TRANSCRIPT_DIGEST,
        DECISION_DIGEST,
        env,
        chain,
        genesis,
        GovernanceExecutionRuntimeSurface::ReloadApply,
        150,
        PreviouslySeenState::FirstSeen,
    );
    let mut input = DurableBackendDecisionInput::from_freshness_input(
        &freshness,
        GovernanceExecutionRuntimeSurface::ReloadApply,
    );
    // Vary decision id to produce distinct record keys where needed.
    input.decision_id = decision_id.to_string();
    input
}

fn devnet_input() -> DurableBackendDecisionInput {
    decision_input(TrustBundleEnvironment::Devnet, CHAIN, GENESIS, SEQUENCE, DECISION)
}

fn identity_devnet() -> DurableReplayRocksDbIdentity {
    DurableReplayRocksDbIdentity::new(TrustBundleEnvironment::Devnet, CHAIN, GENESIS, SEQUENCE)
}

fn open_devnet(dir: &TempDir) -> ProductionDurableReplayRocksDbBackend {
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let (backend, _) =
        ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).expect("open");
    backend
}

fn observed_event(input: &DurableBackendDecisionInput) -> DurableReplayEventInput {
    DurableReplayEventInput::observed_from_decision_input(input)
}

// ===========================================================================
// A — Open / schema tests
// ===========================================================================

#[test]
fn a01_opens_empty_temp_db_and_initializes_metadata() {
    let dir = TempDir::new().unwrap();
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let (backend, outcome) =
        ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).expect("open");
    assert_eq!(outcome, DurableReplayRocksDbOpenOutcome::InitializedEmpty);
    assert_eq!(backend.open_outcome(), DurableReplayRocksDbOpenOutcome::InitializedEmpty);
    assert!(backend.scan_replay_records().unwrap().is_empty());
}

#[test]
fn a02_reopen_initialized_db_same_domain_opens_existing() {
    let dir = TempDir::new().unwrap();
    {
        let _ = open_devnet(&dir);
    }
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let (_, outcome) =
        ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).expect("reopen");
    assert_eq!(outcome, DurableReplayRocksDbOpenOutcome::OpenedExisting);
}

#[test]
fn a03_refuses_wrong_environment() {
    let dir = TempDir::new().unwrap();
    {
        let _ = open_devnet(&dir);
    }
    let id = DurableReplayRocksDbIdentity::new(
        TrustBundleEnvironment::Testnet,
        CHAIN,
        GENESIS,
        SEQUENCE,
    );
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), id);
    let err = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap_err();
    assert_eq!(err, DurableReplayRocksDbError::DomainMismatch { field: "environment" });
}

#[test]
fn a04_refuses_wrong_chain_id() {
    let dir = TempDir::new().unwrap();
    {
        let _ = open_devnet(&dir);
    }
    let id =
        DurableReplayRocksDbIdentity::new(TrustBundleEnvironment::Devnet, "other-chain", GENESIS, SEQUENCE);
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), id);
    let err = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap_err();
    assert_eq!(err, DurableReplayRocksDbError::DomainMismatch { field: "chain_id" });
}

#[test]
fn a05_refuses_wrong_genesis() {
    let dir = TempDir::new().unwrap();
    {
        let _ = open_devnet(&dir);
    }
    let id = DurableReplayRocksDbIdentity::new(
        TrustBundleEnvironment::Devnet,
        CHAIN,
        "wrong-genesis-hash",
        SEQUENCE,
    );
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), id);
    let err = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap_err();
    assert_eq!(err, DurableReplayRocksDbError::DomainMismatch { field: "genesis_hash" });
}

#[test]
fn a06_refuses_wrong_namespace() {
    let dir = TempDir::new().unwrap();
    {
        let _ = open_devnet(&dir);
    }
    let mut id = identity_devnet();
    id.replay_namespace = "different.namespace".to_string();
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), id);
    let err = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap_err();
    assert_eq!(err, DurableReplayRocksDbError::DomainMismatch { field: "replay_namespace" });
}

#[test]
fn a07_refuses_wrong_authority_domain_sequence() {
    let dir = TempDir::new().unwrap();
    {
        let _ = open_devnet(&dir);
    }
    let id =
        DurableReplayRocksDbIdentity::new(TrustBundleEnvironment::Devnet, CHAIN, GENESIS, SEQUENCE + 1);
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), id);
    let err = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap_err();
    assert_eq!(
        err,
        DurableReplayRocksDbError::DomainMismatch { field: "authority_domain_sequence" }
    );
}

#[test]
fn a08_refuses_unsupported_future_schema() {
    let dir = TempDir::new().unwrap();
    {
        let _ = open_devnet(&dir);
    }
    // Overwrite the schema marker with an unsupported future version.
    {
        let db = rocksdb::DB::open_default(dir.path()).unwrap();
        db.put(KEY_SCHEMA, (DURABLE_REPLAY_ROCKSDB_SCHEMA_VERSION + 9).to_le_bytes())
            .unwrap();
    }
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let err = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap_err();
    assert_eq!(
        err,
        DurableReplayRocksDbError::SchemaUnsupported {
            found: DURABLE_REPLAY_ROCKSDB_SCHEMA_VERSION + 9,
            supported: DURABLE_REPLAY_ROCKSDB_SCHEMA_VERSION,
        }
    );
}

#[test]
fn a09_refuses_malformed_schema_marker() {
    let dir = TempDir::new().unwrap();
    {
        let _ = open_devnet(&dir);
    }
    {
        let db = rocksdb::DB::open_default(dir.path()).unwrap();
        db.put(KEY_SCHEMA, b"xx").unwrap(); // not 4 bytes
    }
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let err = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap_err();
    assert_eq!(err, DurableReplayRocksDbError::SchemaMarkerMalformed);
}

#[test]
fn a10_refuses_missing_schema_in_non_empty_db() {
    let dir = TempDir::new().unwrap();
    {
        let mut backend = open_devnet(&dir);
        let ev = observed_event(&devnet_input());
        backend.record_replay_event(&ev).unwrap();
    }
    // Delete the schema + domain markers, leaving a record behind.
    {
        let db = rocksdb::DB::open_default(dir.path()).unwrap();
        db.delete(KEY_SCHEMA).unwrap();
        db.delete(KEY_DOMAIN).unwrap();
    }
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let err = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap_err();
    assert_eq!(err, DurableReplayRocksDbError::SchemaMarkerMissing);
}

#[test]
fn a11_refuses_missing_domain_metadata_when_schema_present() {
    let dir = TempDir::new().unwrap();
    {
        let _ = open_devnet(&dir);
    }
    {
        let db = rocksdb::DB::open_default(dir.path()).unwrap();
        db.delete(KEY_DOMAIN).unwrap();
    }
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let err = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap_err();
    assert_eq!(err, DurableReplayRocksDbError::MetadataMissing);
}

#[test]
fn a12_refuses_corrupted_domain_metadata() {
    let dir = TempDir::new().unwrap();
    {
        let _ = open_devnet(&dir);
    }
    {
        let db = rocksdb::DB::open_default(dir.path()).unwrap();
        db.put(KEY_DOMAIN, b"not-valid-bincode-metadata").unwrap();
    }
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let err = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap_err();
    assert_eq!(err, DurableReplayRocksDbError::MetadataMalformed);
}

#[test]
fn a13_lock_contention_second_open_fails_closed() {
    let dir = TempDir::new().unwrap();
    let _first = open_devnet(&dir);
    // A second open of the same path while the first handle is live must fail.
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let err = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap_err();
    assert!(matches!(err, DurableReplayRocksDbError::RocksDbOpen(_)));
}

#[test]
fn a14_unwritable_path_fails_closed() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    let ro = dir.path().join("readonly");
    std::fs::create_dir(&ro).unwrap();
    std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o500)).unwrap();
    let target = ro.join("db");
    let cfg = DurableReplayRocksDbConfig::source_test(&target, identity_devnet());
    let result = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg);
    // Restore permissions so the temp dir can be cleaned up.
    std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o700)).ok();
    assert!(matches!(result, Err(DurableReplayRocksDbError::RocksDbOpen(_))));
}

#[test]
fn a15_disabled_policy_fails_closed() {
    let dir = TempDir::new().unwrap();
    let cfg = DurableReplayRocksDbConfig::disabled(dir.path(), identity_devnet());
    let err = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap_err();
    assert_eq!(err, DurableReplayRocksDbError::BackendDisabled);
}

#[test]
fn a16_mainnet_identity_refused() {
    let dir = TempDir::new().unwrap();
    let id =
        DurableReplayRocksDbIdentity::new(TrustBundleEnvironment::Mainnet, CHAIN, GENESIS, SEQUENCE);
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), id);
    let err = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap_err();
    assert_eq!(err, DurableReplayRocksDbError::MainNetRefused);
}

#[test]
fn a17_malformed_identity_refused() {
    let dir = TempDir::new().unwrap();
    let id = DurableReplayRocksDbIdentity::new(TrustBundleEnvironment::Devnet, "", GENESIS, SEQUENCE);
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), id);
    let err = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap_err();
    assert_eq!(err, DurableReplayRocksDbError::MalformedIdentity);
}

#[test]
fn a18_testnet_domain_opens_and_binds() {
    let dir = TempDir::new().unwrap();
    let id =
        DurableReplayRocksDbIdentity::new(TrustBundleEnvironment::Testnet, "qbind-testnet", GENESIS, SEQUENCE);
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), id.clone());
    let (backend, outcome) =
        ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).expect("open testnet");
    assert_eq!(outcome, DurableReplayRocksDbOpenOutcome::InitializedEmpty);
    assert_eq!(backend.identity().environment, TrustBundleEnvironment::Testnet);
}

#[test]
fn a19_reopen_after_close_flush_opens_existing() {
    let dir = TempDir::new().unwrap();
    {
        let mut backend = open_devnet(&dir);
        backend.close_or_flush().unwrap();
    }
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let (_, outcome) = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap();
    assert_eq!(outcome, DurableReplayRocksDbOpenOutcome::OpenedExisting);
}

// ===========================================================================
// B — Write / read durability tests
// ===========================================================================

#[test]
fn b01_write_one_record_and_read_it_back() {
    let dir = TempDir::new().unwrap();
    let mut backend = open_devnet(&dir);
    let input = devnet_input();
    let ev = observed_event(&input);
    let out = backend.record_replay_event(&ev).unwrap();
    assert_eq!(out.tag(), "written");
    let read = backend
        .read_replay_record(&durable_backend_key_digest(&input), DurableReplayRecordStage::Observed)
        .unwrap();
    match read {
        DurableReplayRocksDbReadOutcome::Found(r) => {
            assert_eq!(r.record_id, durable_backend_key_digest(&input));
            assert_eq!(r.stage, DurableReplayRecordStage::Observed);
        }
        other => panic!("expected Found, got {other:?}"),
    }
}

#[test]
fn b02_write_survives_close_reopen() {
    let dir = TempDir::new().unwrap();
    let input = devnet_input();
    let key = durable_backend_key_digest(&input);
    {
        let mut backend = open_devnet(&dir);
        backend.record_replay_event(&observed_event(&input)).unwrap();
        backend.close_or_flush().unwrap();
    }
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let (backend, outcome) =
        ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap();
    assert_eq!(outcome, DurableReplayRocksDbOpenOutcome::OpenedExisting);
    assert!(backend
        .read_replay_record(&key, DurableReplayRecordStage::Observed)
        .unwrap()
        .is_found());
}

#[test]
fn b03_multiple_records_survive_reopen_deterministic_order() {
    let dir = TempDir::new().unwrap();
    {
        let mut backend = open_devnet(&dir);
        for i in 0..5u64 {
            let input = decision_input(
                TrustBundleEnvironment::Devnet,
                CHAIN,
                GENESIS,
                SEQUENCE,
                &format!("decision-{i:04}"),
            );
            backend.record_replay_event(&observed_event(&input)).unwrap();
        }
    }
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let (backend, _) = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap();
    let scan1 = backend.scan_replay_records().unwrap();
    let scan2 = backend.scan_replay_records().unwrap();
    assert_eq!(scan1.len(), 5);
    assert_eq!(scan1, scan2, "scan order must be deterministic");
    // Verify records come back in deterministic key-sorted order.
    let keys: Vec<String> = scan1.iter().map(|r| r.record_id.clone()).collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted);
}

#[test]
fn b04_read_missing_record_returns_not_found_without_mutation() {
    let dir = TempDir::new().unwrap();
    let backend = open_devnet(&dir);
    let read = backend
        .read_replay_record("nonexistent-record-id", DurableReplayRecordStage::Observed)
        .unwrap();
    assert_eq!(read, DurableReplayRocksDbReadOutcome::NotFound);
    assert!(backend.scan_replay_records().unwrap().is_empty());
}

#[test]
fn b05_scan_empty_db_returns_empty() {
    let dir = TempDir::new().unwrap();
    let backend = open_devnet(&dir);
    assert!(backend.scan_replay_records().unwrap().is_empty());
}

#[test]
fn b06_scan_populated_db_returns_all_records() {
    let dir = TempDir::new().unwrap();
    let mut backend = open_devnet(&dir);
    for i in 0..3u64 {
        let input = decision_input(
            TrustBundleEnvironment::Devnet,
            CHAIN,
            GENESIS,
            SEQUENCE,
            &format!("d-{i}"),
        );
        backend.record_replay_event(&observed_event(&input)).unwrap();
    }
    assert_eq!(backend.scan_replay_records().unwrap().len(), 3);
}

#[test]
fn b07_flush_reopen_preserves_committed_data() {
    let dir = TempDir::new().unwrap();
    let input = devnet_input();
    {
        let mut backend = open_devnet(&dir);
        backend.record_replay_event(&observed_event(&input)).unwrap();
        backend.close_or_flush().unwrap();
    }
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let (backend, _) = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap();
    assert_eq!(backend.scan_replay_records().unwrap().len(), 1);
}

#[test]
fn b08_observed_then_consumed_stage_persist_and_reopen() {
    let dir = TempDir::new().unwrap();
    let input = devnet_input();
    let key = durable_backend_key_digest(&input);
    let observed_digest;
    {
        let mut backend = open_devnet(&dir);
        let out = backend.record_replay_event(&observed_event(&input)).unwrap();
        observed_digest = out.record().digest.clone();
        let consume =
            DurableReplayEventInput::consumed_from_decision_input(&input, observed_digest.clone());
        let cout = backend.record_replay_event(&consume).unwrap();
        assert_eq!(cout.tag(), "written");
    }
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let (backend, _) = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap();
    assert!(backend
        .read_replay_record(&key, DurableReplayRecordStage::Observed)
        .unwrap()
        .is_found());
    assert!(backend
        .read_replay_record(&key, DurableReplayRecordStage::Consumed)
        .unwrap()
        .is_found());
}

// ===========================================================================
// C — Idempotency / equivocation tests
// ===========================================================================

#[test]
fn c01_duplicate_identical_record_is_idempotent() {
    let dir = TempDir::new().unwrap();
    let mut backend = open_devnet(&dir);
    let ev = observed_event(&devnet_input());
    let first = backend.record_replay_event(&ev).unwrap();
    assert_eq!(first.tag(), "written");
    let second = backend.record_replay_event(&ev).unwrap();
    assert_eq!(second.tag(), "idempotent-duplicate");
    assert_eq!(backend.scan_replay_records().unwrap().len(), 1);
}

#[test]
fn c02_duplicate_identical_record_after_reopen_is_idempotent() {
    let dir = TempDir::new().unwrap();
    let input = devnet_input();
    {
        let mut backend = open_devnet(&dir);
        backend.record_replay_event(&observed_event(&input)).unwrap();
    }
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let (mut backend, _) = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap();
    let out = backend.record_replay_event(&observed_event(&input)).unwrap();
    assert_eq!(out.tag(), "idempotent-duplicate");
    assert_eq!(backend.scan_replay_records().unwrap().len(), 1);
}

#[test]
fn c03_same_id_different_digest_fails_closed_equivocation() {
    let dir = TempDir::new().unwrap();
    let mut backend = open_devnet(&dir);
    let input = devnet_input();
    let mut ev = observed_event(&input);
    backend.record_replay_event(&ev).unwrap();
    // Same record id, different replay_sequence => different digest.
    ev.replay_sequence += 1;
    let err = backend.record_replay_event(&ev).unwrap_err();
    assert_eq!(
        err,
        DurableReplayRocksDbError::Equivocation { record_id: ev.record_id.clone() }
    );
}

#[test]
fn c04_same_id_different_payload_fails_closed() {
    let dir = TempDir::new().unwrap();
    let mut backend = open_devnet(&dir);
    let input = devnet_input();
    let mut ev = observed_event(&input);
    backend.record_replay_event(&ev).unwrap();
    ev.payload_digest = "tampered-payload-digest".to_string();
    let err = backend.record_replay_event(&ev).unwrap_err();
    assert!(matches!(err, DurableReplayRocksDbError::Equivocation { .. }));
}

#[test]
fn c05_equivocation_attempt_does_not_overwrite_original() {
    let dir = TempDir::new().unwrap();
    let mut backend = open_devnet(&dir);
    let input = devnet_input();
    let ev = observed_event(&input);
    let original = backend.record_replay_event(&ev).unwrap().record().clone();
    let mut bad = ev.clone();
    bad.replay_sequence += 99;
    let _ = backend.record_replay_event(&bad).unwrap_err();
    let read = backend
        .read_replay_record(&ev.record_id, DurableReplayRecordStage::Observed)
        .unwrap();
    match read {
        DurableReplayRocksDbReadOutcome::Found(r) => assert_eq!(r, original),
        other => panic!("expected original preserved, got {other:?}"),
    }
}

#[test]
fn c06_original_survives_reopen_after_equivocation_attempt() {
    let dir = TempDir::new().unwrap();
    let input = devnet_input();
    let ev = observed_event(&input);
    let original;
    {
        let mut backend = open_devnet(&dir);
        original = backend.record_replay_event(&ev).unwrap().record().clone();
        let mut bad = ev.clone();
        bad.replay_sequence += 5;
        let _ = backend.record_replay_event(&bad).unwrap_err();
    }
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let (backend, _) = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap();
    let read = backend
        .read_replay_record(&ev.record_id, DurableReplayRecordStage::Observed)
        .unwrap();
    match read {
        DurableReplayRocksDbReadOutcome::Found(r) => assert_eq!(r, original),
        other => panic!("expected original preserved, got {other:?}"),
    }
}

#[test]
fn c07_consume_without_prior_observed_fails_ordering() {
    let dir = TempDir::new().unwrap();
    let mut backend = open_devnet(&dir);
    let input = devnet_input();
    let consume = DurableReplayEventInput::consumed_from_decision_input(&input, "some-prior-digest");
    let err = backend.record_replay_event(&consume).unwrap_err();
    assert!(matches!(err, DurableReplayRocksDbError::OrderingViolation { .. }));
}

#[test]
fn c08_consume_with_wrong_prior_digest_fails_ordering() {
    let dir = TempDir::new().unwrap();
    let mut backend = open_devnet(&dir);
    let input = devnet_input();
    backend.record_replay_event(&observed_event(&input)).unwrap();
    let consume =
        DurableReplayEventInput::consumed_from_decision_input(&input, "wrong-prior-stage-digest");
    let err = backend.record_replay_event(&consume).unwrap_err();
    assert!(matches!(err, DurableReplayRocksDbError::OrderingViolation { .. }));
}

#[test]
fn c09_consume_idempotent_after_reopen() {
    let dir = TempDir::new().unwrap();
    let input = devnet_input();
    let observed_digest;
    {
        let mut backend = open_devnet(&dir);
        observed_digest = backend
            .record_replay_event(&observed_event(&input))
            .unwrap()
            .record()
            .digest
            .clone();
        let consume =
            DurableReplayEventInput::consumed_from_decision_input(&input, observed_digest.clone());
        backend.record_replay_event(&consume).unwrap();
    }
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let (mut backend, _) = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap();
    let consume =
        DurableReplayEventInput::consumed_from_decision_input(&input, observed_digest.clone());
    let out = backend.record_replay_event(&consume).unwrap();
    assert_eq!(out.tag(), "idempotent-duplicate");
}

// ===========================================================================
// D — Atomicity / recovery tests
// ===========================================================================

#[test]
fn d01_simulated_precommit_failure_leaves_no_record() {
    let dir = TempDir::new().unwrap();
    let input = devnet_input();
    {
        let mut backend = open_devnet(&dir);
        let err = backend
            .record_replay_event_simulate_precommit_failure(&observed_event(&input))
            .unwrap_err();
        assert!(matches!(err, DurableReplayRocksDbError::RocksDbIo(_)));
        assert!(backend.scan_replay_records().unwrap().is_empty());
    }
    // Reopen: still no record.
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let (backend, _) = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap();
    assert!(backend.scan_replay_records().unwrap().is_empty());
}

#[test]
fn d02_simulated_partial_stage_residue_fails_open_closed() {
    let dir = TempDir::new().unwrap();
    let input = devnet_input();
    {
        let mut backend = open_devnet(&dir);
        let _ = backend
            .record_replay_event_simulate_partial_stage_failure(&observed_event(&input))
            .unwrap_err();
    }
    // Reopen must fail closed because partial residue is present.
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let err = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap_err();
    assert!(matches!(err, DurableReplayRocksDbError::PartialResidueDetected(_)));
}

#[test]
fn d03_recover_replay_window_rolls_back_partial_residue() {
    let dir = TempDir::new().unwrap();
    let input = devnet_input();
    {
        let mut backend = open_devnet(&dir);
        let _ = backend
            .record_replay_event_simulate_partial_stage_failure(&observed_event(&input))
            .unwrap_err();
        // Same live handle can recover deterministically.
        let outcome = backend.recover_replay_window().unwrap();
        assert!(matches!(
            outcome,
            DurableReplayRocksDbRecoveryOutcome::RolledBackPartialResidue(1)
        ));
    }
    // Reopen now succeeds (residue was rolled back).
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let (backend, outcome) =
        ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap();
    assert_eq!(outcome, DurableReplayRocksDbOpenOutcome::OpenedExisting);
    assert!(backend.scan_replay_records().unwrap().is_empty());
}

#[test]
fn d04_recover_on_clean_db_reports_nothing_to_recover() {
    let dir = TempDir::new().unwrap();
    let mut backend = open_devnet(&dir);
    let outcome = backend.recover_replay_window().unwrap();
    assert_eq!(outcome, DurableReplayRocksDbRecoveryOutcome::NothingToRecover);
}

#[test]
fn d05_post_write_acknowledgement_survives_reopen() {
    let dir = TempDir::new().unwrap();
    let input = devnet_input();
    let key = durable_backend_key_digest(&input);
    {
        let mut backend = open_devnet(&dir);
        let out = backend.record_replay_event(&observed_event(&input)).unwrap();
        assert_eq!(out.tag(), "written"); // acknowledged as written
    }
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let (backend, _) = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap();
    assert!(backend
        .read_replay_record(&key, DurableReplayRecordStage::Observed)
        .unwrap()
        .is_found());
}

#[test]
fn d06_corrupted_record_payload_fails_closed_on_read() {
    let dir = TempDir::new().unwrap();
    let input = devnet_input();
    let key = durable_backend_key_digest(&input);
    {
        let mut backend = open_devnet(&dir);
        backend.record_replay_event(&observed_event(&input)).unwrap();
    }
    // Corrupt the record bytes directly.
    {
        let db = rocksdb::DB::open_default(dir.path()).unwrap();
        let rec_key = durable_replay_rocksdb_record_key(&key, DurableReplayRecordStage::Observed);
        db.put(&rec_key, b"totally-corrupt-record-bytes").unwrap();
    }
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let (backend, _) = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap();
    let err = backend
        .read_replay_record(&key, DurableReplayRecordStage::Observed)
        .unwrap_err();
    assert!(matches!(err, DurableReplayRocksDbError::CorruptRecord(_)));
}

#[test]
fn d07_corrupted_record_digest_fails_closed_on_read() {
    let dir = TempDir::new().unwrap();
    let input = devnet_input();
    let key = durable_backend_key_digest(&input);
    let mut record;
    {
        let mut backend = open_devnet(&dir);
        record = backend
            .record_replay_event(&observed_event(&input))
            .unwrap()
            .record()
            .clone();
    }
    // Tamper a field but keep the (now-stale) stored digest -> digest mismatch.
    record.replay_sequence += 1;
    {
        let db = rocksdb::DB::open_default(dir.path()).unwrap();
        let rec_key = durable_replay_rocksdb_record_key(&key, DurableReplayRecordStage::Observed);
        db.put(&rec_key, bincode::serialize(&record).unwrap()).unwrap();
    }
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let (backend, _) = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap();
    let err = backend
        .read_replay_record(&key, DurableReplayRecordStage::Observed)
        .unwrap_err();
    assert!(matches!(err, DurableReplayRocksDbError::CorruptDigest { .. }));
}

#[test]
fn d08_truncated_record_fails_closed_on_scan() {
    let dir = TempDir::new().unwrap();
    let input = devnet_input();
    let key = durable_backend_key_digest(&input);
    {
        let mut backend = open_devnet(&dir);
        backend.record_replay_event(&observed_event(&input)).unwrap();
    }
    {
        let db = rocksdb::DB::open_default(dir.path()).unwrap();
        let rec_key = durable_replay_rocksdb_record_key(&key, DurableReplayRecordStage::Observed);
        db.put(&rec_key, b"\x01\x02").unwrap(); // truncated
    }
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let (backend, _) = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap();
    let err = backend.scan_replay_records().unwrap_err();
    assert!(matches!(err, DurableReplayRocksDbError::CorruptRecord(_)));
}

#[test]
fn d09_corrupt_record_read_does_not_mutate_other_records() {
    let dir = TempDir::new().unwrap();
    let good = decision_input(TrustBundleEnvironment::Devnet, CHAIN, GENESIS, SEQUENCE, "good");
    let bad = decision_input(TrustBundleEnvironment::Devnet, CHAIN, GENESIS, SEQUENCE, "bad");
    let bad_key = durable_backend_key_digest(&bad);
    {
        let mut backend = open_devnet(&dir);
        backend.record_replay_event(&observed_event(&good)).unwrap();
        backend.record_replay_event(&observed_event(&bad)).unwrap();
    }
    {
        let db = rocksdb::DB::open_default(dir.path()).unwrap();
        let rec_key =
            durable_replay_rocksdb_record_key(&bad_key, DurableReplayRecordStage::Observed);
        db.put(&rec_key, b"corrupt").unwrap();
    }
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let (backend, _) = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap();
    // Reading the good record still works.
    let good_key = durable_backend_key_digest(&good);
    assert!(backend
        .read_replay_record(&good_key, DurableReplayRecordStage::Observed)
        .unwrap()
        .is_found());
    // Reading the corrupt record fails closed.
    assert!(backend
        .read_replay_record(&bad_key, DurableReplayRecordStage::Observed)
        .is_err());
}

// ===========================================================================
// E — Composition with existing Run 238 durable replay stack
// ===========================================================================

#[test]
fn e01_record_id_matches_run238_durable_backend_key_digest() {
    let input = devnet_input();
    let ev = observed_event(&input);
    assert_eq!(ev.record_id, durable_backend_key_digest(&input));
}

#[test]
fn e02_rocksdb_backend_accepts_same_shape_as_fixture() {
    // The event input is derived directly from the Run 238 decision input,
    // proving the RocksDB backend accepts the same valid replay-record shape.
    let dir = TempDir::new().unwrap();
    let mut backend = open_devnet(&dir);
    let input = devnet_input();
    let out = backend.record_replay_event(&observed_event(&input)).unwrap();
    assert_eq!(out.record().record_id, durable_backend_key_digest(&input));
}

#[test]
fn e03_mock_backend_is_trait_compatible() {
    // The mock implements the same trait, proving the surface is mockable.
    let mut mock = MockDurableReplayBackend::new(identity_devnet());
    let input = devnet_input();
    let out = mock.record_replay_event(&observed_event(&input)).unwrap();
    assert_eq!(out.tag(), "written");
    assert_eq!(mock.len(), 1);
    let dup = mock.record_replay_event(&observed_event(&input)).unwrap();
    assert_eq!(dup.tag(), "idempotent-duplicate");
}

#[test]
fn e04_mock_and_rocksdb_agree_on_equivocation() {
    let dir = TempDir::new().unwrap();
    let mut rocks = open_devnet(&dir);
    let mut mock = MockDurableReplayBackend::new(identity_devnet());
    let input = devnet_input();
    let ev = observed_event(&input);
    rocks.record_replay_event(&ev).unwrap();
    mock.record_replay_event(&ev).unwrap();
    let mut bad = ev.clone();
    bad.replay_sequence += 1;
    assert!(matches!(
        rocks.record_replay_event(&bad),
        Err(DurableReplayRocksDbError::Equivocation { .. })
    ));
    assert!(matches!(
        mock.record_replay_event(&bad),
        Err(DurableReplayRocksDbError::Equivocation { .. })
    ));
}

#[test]
fn e05_disabled_policy_default_matches_production_posture() {
    // Default policy is Disabled; the production binary default remains
    // unaffected because opening a disabled config fails closed.
    let dir = TempDir::new().unwrap();
    let cfg = DurableReplayRocksDbConfig::disabled(dir.path(), identity_devnet());
    assert_eq!(cfg.policy, DurableReplayRocksDbPolicy::Disabled);
    assert!(ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).is_err());
}

#[test]
fn e06_production_source_test_policy_is_selectable() {
    let dir = TempDir::new().unwrap();
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    assert_eq!(cfg.policy, DurableReplayRocksDbPolicy::ProductionSourceTest);
    assert!(ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).is_ok());
}

#[test]
fn e07_distinct_decisions_produce_distinct_records() {
    let dir = TempDir::new().unwrap();
    let mut backend = open_devnet(&dir);
    let a = decision_input(TrustBundleEnvironment::Devnet, CHAIN, GENESIS, SEQUENCE, "a");
    let b = decision_input(TrustBundleEnvironment::Devnet, CHAIN, GENESIS, SEQUENCE, "b");
    assert_ne!(durable_backend_key_digest(&a), durable_backend_key_digest(&b));
    backend.record_replay_event(&observed_event(&a)).unwrap();
    backend.record_replay_event(&observed_event(&b)).unwrap();
    assert_eq!(backend.scan_replay_records().unwrap().len(), 2);
}

// ===========================================================================
// F — Security invariants
// ===========================================================================

#[test]
fn f01_event_domain_mismatch_environment_fails_closed() {
    let dir = TempDir::new().unwrap();
    let mut backend = open_devnet(&dir);
    let mut ev = observed_event(&devnet_input());
    ev.identity.environment = TrustBundleEnvironment::Testnet;
    let err = backend.record_replay_event(&ev).unwrap_err();
    assert_eq!(err, DurableReplayRocksDbError::EventDomainMismatch { field: "environment" });
    assert!(backend.scan_replay_records().unwrap().is_empty());
}

#[test]
fn f02_event_domain_mismatch_chain_fails_closed() {
    let dir = TempDir::new().unwrap();
    let mut backend = open_devnet(&dir);
    let mut ev = observed_event(&devnet_input());
    ev.identity.chain_id = "other".to_string();
    let err = backend.record_replay_event(&ev).unwrap_err();
    assert_eq!(err, DurableReplayRocksDbError::EventDomainMismatch { field: "chain_id" });
}

#[test]
fn f03_rejected_write_does_not_persist_anything() {
    // A rejected write (malformed event) records nothing and is non-mutating.
    let dir = TempDir::new().unwrap();
    let mut backend = open_devnet(&dir);
    let mut ev = observed_event(&devnet_input());
    ev.record_id = String::new();
    let err = backend.record_replay_event(&ev).unwrap_err();
    assert_eq!(err, DurableReplayRocksDbError::MalformedEvent);
    assert!(backend.scan_replay_records().unwrap().is_empty());
}

#[test]
fn f04_mainnet_never_enabled_by_this_run() {
    // No source/test path can open a MainNet-bound database.
    let dir = TempDir::new().unwrap();
    for policy_cfg in [
        DurableReplayRocksDbConfig::source_test(
            dir.path(),
            DurableReplayRocksDbIdentity::new(TrustBundleEnvironment::Mainnet, CHAIN, GENESIS, SEQUENCE),
        ),
        DurableReplayRocksDbConfig::disabled(
            dir.path(),
            DurableReplayRocksDbIdentity::new(TrustBundleEnvironment::Mainnet, CHAIN, GENESIS, SEQUENCE),
        ),
    ] {
        assert!(ProductionDurableReplayRocksDbBackend::open_or_initialize(&policy_cfg).is_err());
    }
    assert!(durable_replay_rocksdb_mainnet_remains_refused());
}

#[test]
fn f05_no_hidden_fallback_to_in_memory() {
    // The invariant helper asserts there is no silent fallback path.
    assert!(durable_replay_rocksdb_never_falls_back_to_in_memory());
    // And a genuinely broken open returns a typed error, not a working handle.
    let dir = TempDir::new().unwrap();
    let cfg = DurableReplayRocksDbConfig::disabled(dir.path(), identity_devnet());
    match ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg) {
        Err(DurableReplayRocksDbError::BackendDisabled) => {}
        other => panic!("expected typed BackendDisabled, got {other:?}"),
    }
}

#[test]
fn f06_default_policy_is_disabled() {
    assert_eq!(DurableReplayRocksDbPolicy::default(), DurableReplayRocksDbPolicy::Disabled);
    assert!(!DurableReplayRocksDbPolicy::default().permits_open());
    assert!(durable_replay_rocksdb_default_is_disabled());
}

#[test]
fn f07_schema_version_is_stable() {
    assert_eq!(DURABLE_REPLAY_ROCKSDB_SCHEMA_VERSION, 1);
    assert_eq!(identity_devnet().schema_version, DURABLE_REPLAY_ROCKSDB_SCHEMA_VERSION);
}

// ===========================================================================
// G — C4/C5 taxonomy grep/assertion checks
// ===========================================================================

#[test]
fn g01_run291_is_source_test_not_release_binary_evidence() {
    assert!(durable_replay_rocksdb_is_source_test_not_release_binary_evidence());
}

#[test]
fn g02_evidence_doc_states_source_test_and_c4_c5_open() {
    let doc = include_str!("../../../docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_291.md");
    assert!(doc.contains("Run 291"));
    assert!(doc.contains("source/test"));
    assert!(doc.contains("release-binary evidence") && doc.contains("Run 292"));
    assert!(doc.contains("C4 remains OPEN"));
    assert!(doc.contains("C5 remains OPEN"));
}

#[test]
fn g03_c4_c5_matrix_keeps_production_backend_not_green() {
    let doc = include_str!("../../../docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md");
    assert!(doc.contains("Production durable replay RocksDB backend"));
    // The row must remain Yellow (source-test landed), not Green.
    assert!(doc.contains("C4 remains OPEN") || doc.contains("**C4 remains OPEN**"));
}

#[test]
fn g04_contradiction_doc_has_run291_entry() {
    let doc = include_str!("../../../docs/whitepaper/contradiction.md");
    assert!(doc.contains("Run 291"));
    assert!(doc.contains("C4 remains OPEN; C5 remains OPEN"));
}