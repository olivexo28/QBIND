//! Run 292 — release-binary helper for the Run 291 **production durable replay
//! RocksDB backend**.
//!
//! Release-binary evidence for the Run 291 source/test production durable replay
//! RocksDB backend (`crates/qbind-node/src/pqc_governance_production_durable_replay_rocksdb.rs`).
//! This helper is compiled as a release example and linked against the
//! release-built production library symbols. It exercises the **real** Run 291
//! [`ProductionDurableReplayRocksDbBackend`] against temp-dir RocksDB databases
//! in release mode and proves, per check with PASS/FAIL, the accepted /
//! rejection / idempotency-equivocation / ordering-replay / corruption /
//! non-mutation behavior of the real on-disk backend.
//!
//! The helper remains **dead code** from the production runtime: the production
//! `qbind-node` binary never references it. It opens the backend only through
//! the source/test `DurableReplayRocksDbPolicy::ProductionSourceTest` selector,
//! only for DevNet/TestNet identities, and only against ephemeral temp
//! directories. It never enables any production runtime path, MainNet
//! enablement, custody/RemoteSigner/KMS/HSM signing, on-chain governance proof
//! verification, governance execution engine, validator-set rotation,
//! settlement, or external publication, and it never falls back to an in-memory
//! backend on RocksDB failure.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_292.md`.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

use qbind_node::pqc_governance_authority::GovernanceAuthorityClass;
use qbind_node::pqc_governance_evaluator_replay_durable_backend::{
    durable_backend_key_digest, durable_record_digest, DurableBackendDecisionInput,
    DurableRecordState,
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
use qbind_node::pqc_authority_lifecycle::LocalLifecycleAction;
use qbind_node::pqc_governance_production_durable_replay_rocksdb::{
    durable_replay_rocksdb_default_is_disabled,
    durable_replay_rocksdb_domain_digest,
    durable_replay_rocksdb_is_source_test_not_release_binary_evidence,
    durable_replay_rocksdb_mainnet_remains_refused,
    durable_replay_rocksdb_never_falls_back_to_in_memory, durable_replay_rocksdb_record_digest,
    durable_replay_rocksdb_record_id, durable_replay_rocksdb_record_key, DurableReplayEventInput,
    DurableReplayRecordStage, DurableReplayRocksDbConfig, DurableReplayRocksDbError,
    DurableReplayRocksDbIdentity, DurableReplayRocksDbOpenOutcome, DurableReplayRocksDbPolicy,
    DurableReplayRocksDbReadOutcome, DurableReplayRocksDbRecoveryOutcome,
    DurableReplayRocksDbWriteOutcome, GovernanceProductionDurableReplayBackend,
    MockDurableReplayBackend, ProductionDurableReplayRocksDbBackend,
    DURABLE_REPLAY_ROCKSDB_SCHEMA_VERSION, KEY_DOMAIN, KEY_SCHEMA,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;
use tempfile::TempDir;

// ===========================================================================
// Shared constants / builders (mirror the Run 291 corpus).
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
/// genesis / sequence / decision id so distinct records can be produced.
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
// A — Accepted / compatible release checks
// ===========================================================================

fn a01_open_empty_initializes_metadata() {
    let dir = TempDir::new().unwrap();
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let (backend, outcome) =
        ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).expect("open");
    assert_eq!(outcome, DurableReplayRocksDbOpenOutcome::InitializedEmpty);
    assert_eq!(backend.open_outcome(), DurableReplayRocksDbOpenOutcome::InitializedEmpty);
    assert_eq!(backend.identity().environment, TrustBundleEnvironment::Devnet);
}

fn a02_reopen_same_identity_opens_existing() {
    let dir = TempDir::new().unwrap();
    let _ = open_devnet(&dir);
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let (_, outcome) =
        ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).expect("reopen");
    assert_eq!(outcome, DurableReplayRocksDbOpenOutcome::OpenedExisting);
}

fn a03_write_observed_and_read_back() {
    let dir = TempDir::new().unwrap();
    let mut backend = open_devnet(&dir);
    let input = devnet_input();
    let out = backend.record_replay_event(&observed_event(&input)).unwrap();
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

fn a04_write_consumed_after_observed() {
    let dir = TempDir::new().unwrap();
    let mut backend = open_devnet(&dir);
    let input = devnet_input();
    let observed = backend.record_replay_event(&observed_event(&input)).unwrap();
    let observed_digest = observed.record().digest.clone();
    let consume =
        DurableReplayEventInput::consumed_from_decision_input(&input, observed_digest);
    let out = backend.record_replay_event(&consume).unwrap();
    assert_eq!(out.tag(), "written");
    assert!(backend
        .read_replay_record(&durable_backend_key_digest(&input), DurableReplayRecordStage::Consumed)
        .unwrap()
        .is_found());
}

fn a05_close_reopen_records_survive() {
    let dir = TempDir::new().unwrap();
    let input = devnet_input();
    let key = durable_backend_key_digest(&input);
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
    assert!(backend
        .read_replay_record(&key, DurableReplayRecordStage::Consumed)
        .unwrap()
        .is_found());
}

fn a06_scan_deterministic_order() {
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
    let keys: Vec<String> = scan1.iter().map(|r| r.record_id.clone()).collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted);
}

fn a07_record_id_from_run238_decision_input() {
    let input = devnet_input();
    let ev = observed_event(&input);
    assert_eq!(ev.record_id, durable_backend_key_digest(&input));
    assert_eq!(durable_replay_rocksdb_record_id(&input), durable_backend_key_digest(&input));
    // Payload digest is derived from the Run 238 durable record digest.
    assert_eq!(
        ev.payload_digest,
        durable_record_digest(&input, DurableRecordState::ObservedFresh, 1)
    );
}

fn a08_deterministic_digest_stability() {
    let identity = identity_devnet();
    let input = devnet_input();
    let ev = observed_event(&input);
    let d1 = durable_replay_rocksdb_record_digest(
        &identity,
        &ev.record_id,
        ev.stage,
        ev.prior_stage_digest.as_deref(),
        &ev.payload_digest,
        ev.replay_sequence,
    );
    let d2 = durable_replay_rocksdb_record_digest(
        &identity,
        &ev.record_id,
        ev.stage,
        ev.prior_stage_digest.as_deref(),
        &ev.payload_digest,
        ev.replay_sequence,
    );
    assert_eq!(d1, d2, "record digest must be deterministic");
    assert_eq!(identity.domain_digest(), durable_replay_rocksdb_domain_digest(&identity));
    // The record is persisted with exactly this digest.
    let dir = TempDir::new().unwrap();
    let mut backend = open_devnet(&dir);
    let out = backend.record_replay_event(&ev).unwrap();
    assert_eq!(out.record().digest, d1);
}

fn a09_mock_backend_trait_compatible() {
    let mut mock = MockDurableReplayBackend::new(identity_devnet());
    let input = devnet_input();
    let out = mock.record_replay_event(&observed_event(&input)).unwrap();
    assert_eq!(out.tag(), "written");
    assert_eq!(mock.len(), 1);
    assert!(!mock.is_empty());
    let dup = mock.record_replay_event(&observed_event(&input)).unwrap();
    assert_eq!(dup.tag(), "idempotent-duplicate");
    assert!(mock
        .read_replay_record(&durable_backend_key_digest(&input), DurableReplayRecordStage::Observed)
        .unwrap()
        .is_found());
    assert_eq!(mock.scan_replay_records().unwrap().len(), 1);
}

fn a10_testnet_domain_opens_and_binds() {
    let dir = TempDir::new().unwrap();
    let id = DurableReplayRocksDbIdentity::new(
        TrustBundleEnvironment::Testnet,
        "qbind-testnet",
        GENESIS,
        SEQUENCE,
    );
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), id);
    let (backend, outcome) =
        ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).expect("open testnet");
    assert_eq!(outcome, DurableReplayRocksDbOpenOutcome::InitializedEmpty);
    assert_eq!(backend.identity().environment, TrustBundleEnvironment::Testnet);
}

// ===========================================================================
// B — Rejection / fail-closed release checks
// ===========================================================================

fn b01_default_disabled_refuses_open() {
    let dir = TempDir::new().unwrap();
    let cfg = DurableReplayRocksDbConfig::disabled(dir.path(), identity_devnet());
    assert_eq!(cfg.policy, DurableReplayRocksDbPolicy::Disabled);
    let err = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap_err();
    assert_eq!(err, DurableReplayRocksDbError::BackendDisabled);
}

fn b02_mainnet_identity_refused() {
    let dir = TempDir::new().unwrap();
    let id = DurableReplayRocksDbIdentity::new(
        TrustBundleEnvironment::Mainnet,
        CHAIN,
        GENESIS,
        SEQUENCE,
    );
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), id);
    let err = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap_err();
    assert_eq!(err, DurableReplayRocksDbError::MainNetRefused);
}

fn reopen_wrong(mutate: impl FnOnce(&mut DurableReplayRocksDbIdentity)) -> DurableReplayRocksDbError {
    let dir = TempDir::new().unwrap();
    let _ = open_devnet(&dir);
    let mut id = identity_devnet();
    mutate(&mut id);
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), id);
    ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap_err()
}

fn b03_wrong_environment_refuses_reopen() {
    let err = reopen_wrong(|id| id.environment = TrustBundleEnvironment::Testnet);
    assert!(matches!(err, DurableReplayRocksDbError::DomainMismatch { .. }));
}

fn b04_wrong_chain_refuses_reopen() {
    let err = reopen_wrong(|id| id.chain_id = "other-chain".to_string());
    assert!(matches!(err, DurableReplayRocksDbError::DomainMismatch { .. }));
}

fn b05_wrong_genesis_refuses_reopen() {
    let err = reopen_wrong(|id| id.genesis_hash = "other-genesis".to_string());
    assert!(matches!(err, DurableReplayRocksDbError::DomainMismatch { .. }));
}

fn b06_wrong_namespace_refuses_reopen() {
    let err = reopen_wrong(|id| id.replay_namespace = "other-namespace".to_string());
    assert!(matches!(err, DurableReplayRocksDbError::DomainMismatch { .. }));
}

fn b07_wrong_authority_domain_sequence_refuses_reopen() {
    let err = reopen_wrong(|id| id.authority_domain_sequence += 1);
    assert!(matches!(err, DurableReplayRocksDbError::DomainMismatch { .. }));
}

fn b08_unsupported_future_schema_refuses_open() {
    let dir = TempDir::new().unwrap();
    // Write a future schema marker into an otherwise-metadata-less DB.
    {
        let db = rocksdb::DB::open_default(dir.path()).unwrap();
        db.put(KEY_SCHEMA, (DURABLE_REPLAY_ROCKSDB_SCHEMA_VERSION + 1).to_le_bytes())
            .unwrap();
        db.put(KEY_DOMAIN, b"unused-domain-metadata").unwrap();
    }
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let err = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap_err();
    assert!(matches!(
        err,
        DurableReplayRocksDbError::SchemaUnsupported { .. }
            | DurableReplayRocksDbError::MetadataMalformed
    ));
}

fn b09_malformed_schema_marker_refuses_open() {
    let dir = TempDir::new().unwrap();
    {
        let db = rocksdb::DB::open_default(dir.path()).unwrap();
        db.put(KEY_SCHEMA, b"\x01").unwrap(); // not a valid u32 LE marker
        db.put(KEY_DOMAIN, b"unused").unwrap();
    }
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let err = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap_err();
    assert!(matches!(
        err,
        DurableReplayRocksDbError::SchemaMarkerMalformed
            | DurableReplayRocksDbError::MetadataMalformed
    ));
}

fn b10_missing_metadata_nonempty_db_refuses_open() {
    let dir = TempDir::new().unwrap();
    {
        let db = rocksdb::DB::open_default(dir.path()).unwrap();
        // A non-empty DB carrying an unrelated key but no schema/domain markers.
        db.put(b"qbind.run291.rec.observed.some-id", b"data").unwrap();
    }
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let err = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap_err();
    assert!(matches!(
        err,
        DurableReplayRocksDbError::SchemaMarkerMissing
            | DurableReplayRocksDbError::MetadataMissing
    ));
}

fn b11_corrupted_metadata_refuses_open() {
    let dir = TempDir::new().unwrap();
    let _ = open_devnet(&dir);
    // Corrupt the domain metadata (keep a valid schema marker).
    {
        let db = rocksdb::DB::open_default(dir.path()).unwrap();
        db.put(KEY_DOMAIN, b"totally-corrupt-domain-metadata").unwrap();
    }
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let err = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap_err();
    assert!(matches!(
        err,
        DurableReplayRocksDbError::MetadataMalformed | DurableReplayRocksDbError::DomainMismatch { .. }
    ));
}

fn b12_lock_contention_second_open_fails_closed() {
    let dir = TempDir::new().unwrap();
    let _held = open_devnet(&dir); // keep the DB lock held.
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let err = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap_err();
    assert!(matches!(err, DurableReplayRocksDbError::RocksDbOpen(_)));
}

fn b13_malformed_identity_refused() {
    let dir = TempDir::new().unwrap();
    let id = DurableReplayRocksDbIdentity::new(TrustBundleEnvironment::Devnet, "", GENESIS, SEQUENCE);
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), id);
    let err = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap_err();
    assert_eq!(err, DurableReplayRocksDbError::MalformedIdentity);
}

// ===========================================================================
// C — Idempotency / equivocation release checks
// ===========================================================================

fn c01_duplicate_observed_idempotent() {
    let dir = TempDir::new().unwrap();
    let mut backend = open_devnet(&dir);
    let ev = observed_event(&devnet_input());
    assert_eq!(backend.record_replay_event(&ev).unwrap().tag(), "written");
    assert_eq!(backend.record_replay_event(&ev).unwrap().tag(), "idempotent-duplicate");
    assert_eq!(backend.scan_replay_records().unwrap().len(), 1);
}

fn c02_duplicate_observed_after_reopen_idempotent() {
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

fn c03_duplicate_consumed_idempotent() {
    let dir = TempDir::new().unwrap();
    let mut backend = open_devnet(&dir);
    let input = devnet_input();
    let observed_digest = backend
        .record_replay_event(&observed_event(&input))
        .unwrap()
        .record()
        .digest
        .clone();
    let consume = DurableReplayEventInput::consumed_from_decision_input(&input, observed_digest);
    assert_eq!(backend.record_replay_event(&consume).unwrap().tag(), "written");
    assert_eq!(
        backend.record_replay_event(&consume).unwrap().tag(),
        "idempotent-duplicate"
    );
}

fn c04_duplicate_consumed_after_reopen_idempotent() {
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
    let consume = DurableReplayEventInput::consumed_from_decision_input(&input, observed_digest);
    assert_eq!(
        backend.record_replay_event(&consume).unwrap().tag(),
        "idempotent-duplicate"
    );
}

fn c05_same_id_different_sequence_is_equivocation() {
    let dir = TempDir::new().unwrap();
    let mut backend = open_devnet(&dir);
    let mut ev = observed_event(&devnet_input());
    backend.record_replay_event(&ev).unwrap();
    ev.replay_sequence += 1;
    let err = backend.record_replay_event(&ev).unwrap_err();
    assert!(matches!(err, DurableReplayRocksDbError::Equivocation { .. }));
}

fn c06_same_id_different_payload_is_equivocation() {
    let dir = TempDir::new().unwrap();
    let mut backend = open_devnet(&dir);
    let mut ev = observed_event(&devnet_input());
    backend.record_replay_event(&ev).unwrap();
    ev.payload_digest = "tampered-payload-digest".to_string();
    let err = backend.record_replay_event(&ev).unwrap_err();
    assert!(matches!(err, DurableReplayRocksDbError::Equivocation { .. }));
}

fn c07_equivocation_does_not_overwrite_original() {
    let dir = TempDir::new().unwrap();
    let mut backend = open_devnet(&dir);
    let ev = observed_event(&devnet_input());
    let original = backend.record_replay_event(&ev).unwrap().record().clone();
    let mut bad = ev.clone();
    bad.replay_sequence += 99;
    let _ = backend.record_replay_event(&bad).unwrap_err();
    match backend
        .read_replay_record(&ev.record_id, DurableReplayRecordStage::Observed)
        .unwrap()
    {
        DurableReplayRocksDbReadOutcome::Found(r) => assert_eq!(r, original),
        other => panic!("expected original preserved, got {other:?}"),
    }
}

fn c08_original_survives_reopen_after_equivocation() {
    let dir = TempDir::new().unwrap();
    let ev = observed_event(&devnet_input());
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
    match backend
        .read_replay_record(&ev.record_id, DurableReplayRecordStage::Observed)
        .unwrap()
    {
        DurableReplayRocksDbReadOutcome::Found(r) => assert_eq!(r, original),
        other => panic!("expected original preserved, got {other:?}"),
    }
}

// ===========================================================================
// D — Ordering / replay release checks
// ===========================================================================

fn d01_consumed_before_observed_fails_ordering() {
    let dir = TempDir::new().unwrap();
    let mut backend = open_devnet(&dir);
    let input = devnet_input();
    let consume = DurableReplayEventInput::consumed_from_decision_input(&input, "prior-digest");
    let err = backend.record_replay_event(&consume).unwrap_err();
    assert!(matches!(err, DurableReplayRocksDbError::OrderingViolation { .. }));
    assert!(backend.scan_replay_records().unwrap().is_empty());
}

fn d02_consumed_wrong_prior_digest_fails_ordering() {
    let dir = TempDir::new().unwrap();
    let mut backend = open_devnet(&dir);
    let input = devnet_input();
    backend.record_replay_event(&observed_event(&input)).unwrap();
    let consume =
        DurableReplayEventInput::consumed_from_decision_input(&input, "wrong-prior-stage-digest");
    let err = backend.record_replay_event(&consume).unwrap_err();
    assert!(matches!(err, DurableReplayRocksDbError::OrderingViolation { .. }));
}

fn d03_read_missing_returns_not_found_no_mutation() {
    let dir = TempDir::new().unwrap();
    let backend = open_devnet(&dir);
    let read = backend
        .read_replay_record("nonexistent-record-id", DurableReplayRecordStage::Observed)
        .unwrap();
    assert_eq!(read, DurableReplayRocksDbReadOutcome::NotFound);
    assert!(backend.scan_replay_records().unwrap().is_empty());
}

fn d04_scan_empty_returns_empty() {
    let dir = TempDir::new().unwrap();
    let backend = open_devnet(&dir);
    assert!(backend.scan_replay_records().unwrap().is_empty());
}

fn d05_partial_residue_detected_at_open() {
    let dir = TempDir::new().unwrap();
    let input = devnet_input();
    {
        let mut backend = open_devnet(&dir);
        let _ = backend
            .record_replay_event_simulate_partial_stage_failure(&observed_event(&input))
            .unwrap_err();
    }
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let err = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap_err();
    assert!(matches!(err, DurableReplayRocksDbError::PartialResidueDetected(_)));
}

fn d06_recover_rolls_back_safe_residue() {
    let dir = TempDir::new().unwrap();
    let input = devnet_input();
    {
        let mut backend = open_devnet(&dir);
        let _ = backend
            .record_replay_event_simulate_partial_stage_failure(&observed_event(&input))
            .unwrap_err();
        let outcome = backend.recover_replay_window().unwrap();
        assert!(matches!(
            outcome,
            DurableReplayRocksDbRecoveryOutcome::RolledBackPartialResidue(1)
        ));
    }
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let (backend, outcome) =
        ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap();
    assert_eq!(outcome, DurableReplayRocksDbOpenOutcome::OpenedExisting);
    assert!(backend.scan_replay_records().unwrap().is_empty());
}

fn d07_recover_clean_db_nothing_to_recover() {
    let dir = TempDir::new().unwrap();
    let mut backend = open_devnet(&dir);
    let outcome = backend.recover_replay_window().unwrap();
    assert_eq!(outcome, DurableReplayRocksDbRecoveryOutcome::NothingToRecover);
}

fn d08_precommit_failure_leaves_no_record() {
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
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let (backend, _) = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap();
    assert!(backend.scan_replay_records().unwrap().is_empty());
}

// ===========================================================================
// E — Corruption release checks
// ===========================================================================

fn e01_mutated_payload_fails_closed_on_read() {
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
        db.put(&rec_key, b"totally-corrupt-record-bytes").unwrap();
    }
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let (backend, _) = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap();
    let err = backend
        .read_replay_record(&key, DurableReplayRecordStage::Observed)
        .unwrap_err();
    assert!(matches!(err, DurableReplayRocksDbError::CorruptRecord(_)));
}

fn e02_stale_digest_fails_closed() {
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
    record.replay_sequence += 1; // keep the now-stale stored digest.
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

fn e03_truncated_record_fails_closed_on_scan() {
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
        db.put(&rec_key, b"\x01\x02").unwrap();
    }
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let (backend, _) = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap();
    let err = backend.scan_replay_records().unwrap_err();
    assert!(matches!(err, DurableReplayRocksDbError::CorruptRecord(_)));
}

fn e04_corrupt_record_healthy_sibling_still_reads() {
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
    let good_key = durable_backend_key_digest(&good);
    assert!(backend
        .read_replay_record(&good_key, DurableReplayRecordStage::Observed)
        .unwrap()
        .is_found());
    assert!(backend
        .read_replay_record(&bad_key, DurableReplayRecordStage::Observed)
        .is_err());
}

fn e05_corrupted_metadata_fails_closed() {
    let dir = TempDir::new().unwrap();
    let _ = open_devnet(&dir);
    {
        let db = rocksdb::DB::open_default(dir.path()).unwrap();
        db.put(KEY_DOMAIN, b"corrupt-domain-metadata").unwrap();
    }
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let err = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap_err();
    assert!(matches!(
        err,
        DurableReplayRocksDbError::MetadataMalformed | DurableReplayRocksDbError::DomainMismatch { .. }
    ));
}

fn e06_corruption_never_falls_back_to_in_memory() {
    // A corrupt record surfaces a typed error, never a silent in-memory fallback.
    assert!(durable_replay_rocksdb_never_falls_back_to_in_memory());
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
        db.put(&rec_key, b"corrupt").unwrap();
    }
    let cfg = DurableReplayRocksDbConfig::source_test(dir.path(), identity_devnet());
    let (backend, _) = ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap();
    match backend.read_replay_record(&key, DurableReplayRecordStage::Observed) {
        Err(DurableReplayRocksDbError::CorruptRecord(_)) => {}
        other => panic!("expected typed CorruptRecord, got {other:?}"),
    }
}

// ===========================================================================
// F — Non-mutation / no-authority-extension release checks
// ===========================================================================

fn f01_invariant_no_in_memory_fallback() {
    assert!(durable_replay_rocksdb_never_falls_back_to_in_memory());
}

fn f02_invariant_default_disabled() {
    assert!(durable_replay_rocksdb_default_is_disabled());
    assert_eq!(DurableReplayRocksDbPolicy::default(), DurableReplayRocksDbPolicy::Disabled);
    assert!(!DurableReplayRocksDbPolicy::default().permits_open());
}

fn f03_invariant_mainnet_refused() {
    assert!(durable_replay_rocksdb_mainnet_remains_refused());
    // No source/test path can open a MainNet database.
    let dir = TempDir::new().unwrap();
    let cfg = DurableReplayRocksDbConfig::source_test(
        dir.path(),
        DurableReplayRocksDbIdentity::new(TrustBundleEnvironment::Mainnet, CHAIN, GENESIS, SEQUENCE),
    );
    assert!(ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).is_err());
}

fn f04_invariant_source_test_not_release_evidence_flag() {
    // The Run 291 module self-describes as source/test; Run 292 supplies the
    // release-binary evidence externally (this helper + harness).
    assert!(durable_replay_rocksdb_is_source_test_not_release_binary_evidence());
}

fn f05_rejected_write_is_non_mutating() {
    let dir = TempDir::new().unwrap();
    let mut backend = open_devnet(&dir);
    let mut ev = observed_event(&devnet_input());
    ev.record_id = String::new();
    let err = backend.record_replay_event(&ev).unwrap_err();
    assert_eq!(err, DurableReplayRocksDbError::MalformedEvent);
    assert!(backend.scan_replay_records().unwrap().is_empty());
}

fn f06_event_domain_mismatch_is_non_mutating() {
    let dir = TempDir::new().unwrap();
    let mut backend = open_devnet(&dir);
    let mut ev = observed_event(&devnet_input());
    ev.identity.environment = TrustBundleEnvironment::Testnet;
    let err = backend.record_replay_event(&ev).unwrap_err();
    assert_eq!(err, DurableReplayRocksDbError::EventDomainMismatch { field: "environment" });
    assert!(backend.scan_replay_records().unwrap().is_empty());
}

// ===========================================================================
// G — Release symbol reachability probe
// ===========================================================================

fn g01_release_symbol_reachability_probe() {
    // Touch every Run 291 production symbol the harness greps for, in release
    // mode, so the release helper genuinely exercises the production library.
    let identity: DurableReplayRocksDbIdentity = identity_devnet();
    let _domain: String = durable_replay_rocksdb_domain_digest(&identity);
    let input = devnet_input();
    let record_id: String = durable_replay_rocksdb_record_id(&input);
    assert_eq!(record_id, durable_backend_key_digest(&input));

    let dir = TempDir::new().unwrap();
    let cfg: DurableReplayRocksDbConfig =
        DurableReplayRocksDbConfig::source_test(dir.path(), identity.clone());
    assert_eq!(cfg.policy, DurableReplayRocksDbPolicy::ProductionSourceTest);
    let (mut backend, open_outcome): (ProductionDurableReplayRocksDbBackend, DurableReplayRocksDbOpenOutcome) =
        ProductionDurableReplayRocksDbBackend::open_or_initialize(&cfg).unwrap();
    assert_eq!(open_outcome, DurableReplayRocksDbOpenOutcome::InitializedEmpty);

    let ev: DurableReplayEventInput = observed_event(&input);
    let write: DurableReplayRocksDbWriteOutcome = backend.record_replay_event(&ev).unwrap();
    let observed_digest = write.record().digest.clone();
    assert_eq!(
        observed_digest,
        durable_replay_rocksdb_record_digest(
            &identity,
            &ev.record_id,
            ev.stage,
            ev.prior_stage_digest.as_deref(),
            &ev.payload_digest,
            ev.replay_sequence,
        )
    );

    let consume = DurableReplayEventInput::consumed_from_decision_input(&input, observed_digest);
    let _ = backend.record_replay_event(&consume).unwrap();

    let read: DurableReplayRocksDbReadOutcome = backend
        .read_replay_record(&record_id, DurableReplayRecordStage::Consumed)
        .unwrap();
    assert!(read.is_found());
    let scan = backend.scan_replay_records().unwrap();
    assert_eq!(scan.len(), 2);
    let recovery: DurableReplayRocksDbRecoveryOutcome = backend.recover_replay_window().unwrap();
    assert_eq!(recovery, DurableReplayRocksDbRecoveryOutcome::NothingToRecover);
    backend.close_or_flush().unwrap();

    // Mock backend implements the same trait surface.
    let mut mock: MockDurableReplayBackend = MockDurableReplayBackend::new(identity);
    assert_eq!(mock.record_replay_event(&ev).unwrap().tag(), "written");

    // Error taxonomy is reachable and typed.
    let err: DurableReplayRocksDbError = DurableReplayRocksDbError::BackendDisabled;
    assert_eq!(err, DurableReplayRocksDbError::BackendDisabled);
    assert_eq!(DURABLE_REPLAY_ROCKSDB_SCHEMA_VERSION, 1);

    // Invariant helpers.
    assert!(durable_replay_rocksdb_never_falls_back_to_in_memory());
    assert!(durable_replay_rocksdb_default_is_disabled());
    assert!(durable_replay_rocksdb_mainnet_remains_refused());
    assert!(durable_replay_rocksdb_is_source_test_not_release_binary_evidence());
}

// ===========================================================================
// Harness
// ===========================================================================

fn run_case(table: &str, name: &str, f: fn(), rows: &mut Vec<(String, String, bool)>) {
    let ok = catch_unwind(AssertUnwindSafe(f)).is_ok();
    println!("case {table} {name} {}", if ok { "PASS" } else { "FAIL" });
    rows.push((table.to_string(), name.to_string(), ok));
}

fn main() {
    let outdir = env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(
            "docs/devnet/run_292_production_durable_replay_rocksdb_release_binary/helper_evidence/run_292",
        )
    });
    fs::create_dir_all(outdir.join("fixtures")).expect("create helper output directory");

    let cases: &[(&str, &str, fn())] = &[
        ("accepted_compatible", "a01_open_empty_initializes_metadata", a01_open_empty_initializes_metadata as fn()),
        ("accepted_compatible", "a02_reopen_same_identity_opens_existing", a02_reopen_same_identity_opens_existing as fn()),
        ("accepted_compatible", "a03_write_observed_and_read_back", a03_write_observed_and_read_back as fn()),
        ("accepted_compatible", "a04_write_consumed_after_observed", a04_write_consumed_after_observed as fn()),
        ("accepted_compatible", "a05_close_reopen_records_survive", a05_close_reopen_records_survive as fn()),
        ("accepted_compatible", "a06_scan_deterministic_order", a06_scan_deterministic_order as fn()),
        ("accepted_compatible", "a07_record_id_from_run238_decision_input", a07_record_id_from_run238_decision_input as fn()),
        ("accepted_compatible", "a08_deterministic_digest_stability", a08_deterministic_digest_stability as fn()),
        ("accepted_compatible", "a09_mock_backend_trait_compatible", a09_mock_backend_trait_compatible as fn()),
        ("accepted_compatible", "a10_testnet_domain_opens_and_binds", a10_testnet_domain_opens_and_binds as fn()),
        ("rejection_fail_closed", "b01_default_disabled_refuses_open", b01_default_disabled_refuses_open as fn()),
        ("rejection_fail_closed", "b02_mainnet_identity_refused", b02_mainnet_identity_refused as fn()),
        ("rejection_fail_closed", "b03_wrong_environment_refuses_reopen", b03_wrong_environment_refuses_reopen as fn()),
        ("rejection_fail_closed", "b04_wrong_chain_refuses_reopen", b04_wrong_chain_refuses_reopen as fn()),
        ("rejection_fail_closed", "b05_wrong_genesis_refuses_reopen", b05_wrong_genesis_refuses_reopen as fn()),
        ("rejection_fail_closed", "b06_wrong_namespace_refuses_reopen", b06_wrong_namespace_refuses_reopen as fn()),
        ("rejection_fail_closed", "b07_wrong_authority_domain_sequence_refuses_reopen", b07_wrong_authority_domain_sequence_refuses_reopen as fn()),
        ("rejection_fail_closed", "b08_unsupported_future_schema_refuses_open", b08_unsupported_future_schema_refuses_open as fn()),
        ("rejection_fail_closed", "b09_malformed_schema_marker_refuses_open", b09_malformed_schema_marker_refuses_open as fn()),
        ("rejection_fail_closed", "b10_missing_metadata_nonempty_db_refuses_open", b10_missing_metadata_nonempty_db_refuses_open as fn()),
        ("rejection_fail_closed", "b11_corrupted_metadata_refuses_open", b11_corrupted_metadata_refuses_open as fn()),
        ("rejection_fail_closed", "b12_lock_contention_second_open_fails_closed", b12_lock_contention_second_open_fails_closed as fn()),
        ("rejection_fail_closed", "b13_malformed_identity_refused", b13_malformed_identity_refused as fn()),
        ("idempotency_equivocation", "c01_duplicate_observed_idempotent", c01_duplicate_observed_idempotent as fn()),
        ("idempotency_equivocation", "c02_duplicate_observed_after_reopen_idempotent", c02_duplicate_observed_after_reopen_idempotent as fn()),
        ("idempotency_equivocation", "c03_duplicate_consumed_idempotent", c03_duplicate_consumed_idempotent as fn()),
        ("idempotency_equivocation", "c04_duplicate_consumed_after_reopen_idempotent", c04_duplicate_consumed_after_reopen_idempotent as fn()),
        ("idempotency_equivocation", "c05_same_id_different_sequence_is_equivocation", c05_same_id_different_sequence_is_equivocation as fn()),
        ("idempotency_equivocation", "c06_same_id_different_payload_is_equivocation", c06_same_id_different_payload_is_equivocation as fn()),
        ("idempotency_equivocation", "c07_equivocation_does_not_overwrite_original", c07_equivocation_does_not_overwrite_original as fn()),
        ("idempotency_equivocation", "c08_original_survives_reopen_after_equivocation", c08_original_survives_reopen_after_equivocation as fn()),
        ("ordering_replay", "d01_consumed_before_observed_fails_ordering", d01_consumed_before_observed_fails_ordering as fn()),
        ("ordering_replay", "d02_consumed_wrong_prior_digest_fails_ordering", d02_consumed_wrong_prior_digest_fails_ordering as fn()),
        ("ordering_replay", "d03_read_missing_returns_not_found_no_mutation", d03_read_missing_returns_not_found_no_mutation as fn()),
        ("ordering_replay", "d04_scan_empty_returns_empty", d04_scan_empty_returns_empty as fn()),
        ("ordering_replay", "d05_partial_residue_detected_at_open", d05_partial_residue_detected_at_open as fn()),
        ("ordering_replay", "d06_recover_rolls_back_safe_residue", d06_recover_rolls_back_safe_residue as fn()),
        ("ordering_replay", "d07_recover_clean_db_nothing_to_recover", d07_recover_clean_db_nothing_to_recover as fn()),
        ("ordering_replay", "d08_precommit_failure_leaves_no_record", d08_precommit_failure_leaves_no_record as fn()),
        ("corruption", "e01_mutated_payload_fails_closed_on_read", e01_mutated_payload_fails_closed_on_read as fn()),
        ("corruption", "e02_stale_digest_fails_closed", e02_stale_digest_fails_closed as fn()),
        ("corruption", "e03_truncated_record_fails_closed_on_scan", e03_truncated_record_fails_closed_on_scan as fn()),
        ("corruption", "e04_corrupt_record_healthy_sibling_still_reads", e04_corrupt_record_healthy_sibling_still_reads as fn()),
        ("corruption", "e05_corrupted_metadata_fails_closed", e05_corrupted_metadata_fails_closed as fn()),
        ("corruption", "e06_corruption_never_falls_back_to_in_memory", e06_corruption_never_falls_back_to_in_memory as fn()),
        ("non_mutation", "f01_invariant_no_in_memory_fallback", f01_invariant_no_in_memory_fallback as fn()),
        ("non_mutation", "f02_invariant_default_disabled", f02_invariant_default_disabled as fn()),
        ("non_mutation", "f03_invariant_mainnet_refused", f03_invariant_mainnet_refused as fn()),
        ("non_mutation", "f04_invariant_source_test_not_release_evidence_flag", f04_invariant_source_test_not_release_evidence_flag as fn()),
        ("non_mutation", "f05_rejected_write_is_non_mutating", f05_rejected_write_is_non_mutating as fn()),
        ("non_mutation", "f06_event_domain_mismatch_is_non_mutating", f06_event_domain_mismatch_is_non_mutating as fn()),
        ("reachability", "g01_release_symbol_reachability_probe", g01_release_symbol_reachability_probe as fn()),
    ];

    let mut rows: Vec<(String, String, bool)> = Vec::new();
    for (table, name, f) in cases {
        run_case(table, name, *f, &mut rows);
    }

    let mut tables = BTreeMap::<String, (usize, usize)>::new();
    for (table, _name, ok) in &rows {
        let entry = tables.entry(table.clone()).or_insert((0, 0));
        if *ok {
            entry.0 += 1;
        } else {
            entry.1 += 1;
        }
    }
    let total_pass: usize = rows.iter().filter(|(_, _, ok)| *ok).count();
    let total_fail = rows.len() - total_pass;

    let mut summary = String::new();
    summary.push_str("Run 292 production durable replay RocksDB backend release helper\n");
    summary.push_str(&format!(
        "verdict: {}\n",
        if total_fail == 0 { "PASS" } else { "FAIL" }
    ));
    summary.push_str(
        "backend: crates/qbind-node/src/pqc_governance_production_durable_replay_rocksdb.rs (Run 291 ProductionDurableReplayRocksDbBackend)\n",
    );
    summary.push_str(
        "mode: real on-disk RocksDB, source-test policy (ProductionSourceTest), DevNet/TestNet temp-dir databases only; MainNet refused; default Disabled; every failure is a typed error, never a silent substitution of an in-memory backend\n",
    );
    for (table, (pass, fail)) in &tables {
        summary.push_str(&format!("table {table} pass={pass} fail={fail}\n"));
    }
    summary.push_str(&format!("total_pass: {total_pass}\n"));
    summary.push_str(&format!("total_fail: {total_fail}\n"));

    fs::write(outdir.join("helper_summary.txt"), &summary).expect("write helper summary");

    // Deterministic-digest fixture for cross-invocation comparison by the harness.
    let identity = identity_devnet();
    let input = devnet_input();
    let ev = observed_event(&input);
    let record_digest = durable_replay_rocksdb_record_digest(
        &identity,
        &ev.record_id,
        ev.stage,
        ev.prior_stage_digest.as_deref(),
        &ev.payload_digest,
        ev.replay_sequence,
    );
    fs::write(
        outdir.join("fixtures/run_292_deterministic_digests.txt"),
        format!(
            "domain_digest {}\nrecord_id {}\nobserved_record_digest {}\n",
            identity.domain_digest(),
            ev.record_id,
            record_digest
        ),
    )
    .expect("write digest fixture");

    print!("{summary}");
    if total_fail != 0 {
        std::process::exit(1);
    }
}