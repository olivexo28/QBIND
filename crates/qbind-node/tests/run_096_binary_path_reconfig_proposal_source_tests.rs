//! Run 096 — integration tests for the local-operator-gated canonical
//! reconfig proposal source on the binary consensus path.
//!
//! These tests pin the public-API contract introduced by Run 096:
//!
//! - `BinaryConsensusLoopConfig::with_reconfig_proposal(...)` accepts a
//!   `BinaryReconfigProposalConfig { target_epoch }` and the binary
//!   loop arms it on the engine at startup via
//!   `BasicHotStuffEngine::set_pending_reconfig_next_epoch`. The
//!   intent is single-shot: the engine emits exactly one canonical
//!   `PAYLOAD_KIND_RECONFIG` block carrying that exact `next_epoch`,
//!   then returns to normal proposals.
//! - Default (no `with_reconfig_proposal` call) is bit-equivalent to
//!   pre-Run-096 behaviour: only normal blocks are proposed.
//! - End-to-end: a single-validator binary loop with an armed
//!   reconfig intent emits a canonical reconfig proposal, the Run 095
//!   detector classifies the committed reconfig block, the engine
//!   transitions epoch via the existing `transition_to_epoch`
//!   machinery, and the Run 094 persistence hook writes
//!   `meta:current_epoch = CommittedEpoch(N)` through the supplied
//!   `ConsensusStorage` handle. No synthetic / fabricated epoch.
//!
//! Run 096 makes ZERO change to:
//! - `pqc_trust_activation::ActivationContext` (`current_epoch:
//!   None` constructions are unchanged across the tree);
//! - the canonical reconfig wire format (uses existing
//!   `BlockHeader.payload_kind` + `next_epoch`);
//! - Run 091/092 `CurrentEpochUnavailable` fail-closed activation.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::timeout;

use qbind_consensus::ids::ValidatorId;
use qbind_node::binary_consensus_loop::{
    derive_reconfig_proposal_from_cli_flag, spawn_binary_consensus_loop,
    BinaryConsensusLoopConfig, BinaryReconfigProposalConfig, ReconfigProposalCliError,
};
use qbind_node::metrics::NodeMetrics;
use qbind_node::storage::{ConsensusStorage, InMemoryConsensusStorage};

// ============================================================================
// Tests — `BinaryConsensusLoopConfig::with_reconfig_proposal` builder
// ============================================================================

/// The builder records the intent so a later `run_binary_consensus_loop`
/// invocation can install it on the engine.
#[test]
fn run_096_with_reconfig_proposal_records_intent() {
    let cfg = BinaryConsensusLoopConfig::new(ValidatorId::new(0), 1).with_reconfig_proposal(
        BinaryReconfigProposalConfig { target_epoch: 1 },
    );
    assert_eq!(
        cfg.reconfig_proposal,
        Some(BinaryReconfigProposalConfig { target_epoch: 1 })
    );
}

/// Default config has no reconfig proposal armed. Pre-Run-096
/// behaviour must be preserved bit-for-bit when the operator does not
/// pass the flag.
#[test]
fn run_096_default_config_has_no_reconfig_proposal() {
    let cfg = BinaryConsensusLoopConfig::new(ValidatorId::new(0), 1);
    assert_eq!(cfg.reconfig_proposal, None);
}

// ============================================================================
// Tests — end-to-end single-validator loop with armed reconfig intent
// ============================================================================

/// End-to-end: a single-validator binary loop with `target_epoch = 1`
/// commits the canonical reconfig block, transitions the engine epoch
/// from 0 to 1 via the existing engine machinery (Run 095 detector
/// path), and the Run 094 persistence hook records
/// `CommittedEpoch(1)` to the supplied `ConsensusStorage`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_096_single_validator_reconfig_commits_and_persists() {
    let storage: Arc<dyn ConsensusStorage> = Arc::new(InMemoryConsensusStorage::new());
    // Before: storage holds no committed epoch (Run 091/092 invariant).
    assert_eq!(storage.get_current_epoch().expect("read ok"), None);

    let cfg = BinaryConsensusLoopConfig::new(ValidatorId::new(0), 1)
        .with_tick_interval(Duration::from_millis(5))
        .with_max_ticks(40)
        .with_consensus_storage(Arc::clone(&storage))
        .with_reconfig_proposal(BinaryReconfigProposalConfig { target_epoch: 1 });

    let (_shutdown_tx, shutdown_rx) = watch::channel(());
    let metrics = Arc::new(NodeMetrics::new());
    let (handle, _progress) = spawn_binary_consensus_loop(cfg, shutdown_rx, metrics);

    let final_progress = timeout(Duration::from_secs(5), handle)
        .await
        .expect("loop did not finish within 5s")
        .expect("loop task panicked");

    // The loop must have made forward progress (at least one
    // proposal, at least one commit, view advanced past 0).
    assert!(
        final_progress.proposals_emitted >= 1,
        "expected ≥1 proposal emitted, got {}",
        final_progress.proposals_emitted
    );
    assert!(
        final_progress.commits >= 1,
        "expected ≥1 commit (the canonical reconfig block), got {}",
        final_progress.commits
    );
    assert!(
        final_progress.current_view > 0,
        "expected view to advance past 0, got {}",
        final_progress.current_view
    );

    // After: storage must hold the canonical CommittedEpoch(1) record
    // written through `apply_epoch_transition_atomic`. This is the
    // entire Run 094 + Run 095 + Run 096 chain landing end-to-end.
    let persisted = storage.get_current_epoch().expect("storage read ok");
    assert_eq!(
        persisted,
        Some(1),
        "Run 094 must persist CommittedEpoch(1) after the canonical \
         reconfig block commits; got {:?}",
        persisted
    );
}

/// Negative: a single-validator binary loop with NO reconfig intent
/// armed commits only normal blocks; the engine epoch stays at 0 and
/// the storage `current_epoch` record stays
/// `PresentNoCommittedEpoch`. This is the pre-Run-096 default path
/// and Run 096 must not regress it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_096_default_no_reconfig_intent_does_not_persist_epoch() {
    let storage: Arc<dyn ConsensusStorage> = Arc::new(InMemoryConsensusStorage::new());
    assert_eq!(storage.get_current_epoch().expect("read ok"), None);

    let cfg = BinaryConsensusLoopConfig::new(ValidatorId::new(0), 1)
        .with_tick_interval(Duration::from_millis(5))
        .with_max_ticks(40)
        .with_consensus_storage(Arc::clone(&storage));
    assert_eq!(cfg.reconfig_proposal, None);

    let (_shutdown_tx, shutdown_rx) = watch::channel(());
    let metrics = Arc::new(NodeMetrics::new());
    let (handle, _progress) = spawn_binary_consensus_loop(cfg, shutdown_rx, metrics);

    let final_progress = timeout(Duration::from_secs(5), handle)
        .await
        .expect("loop did not finish within 5s")
        .expect("loop task panicked");

    // Loop must still make forward progress with normal blocks.
    assert!(
        final_progress.commits >= 1,
        "default path must still commit normal blocks; got commits={}",
        final_progress.commits
    );

    // Storage must remain `PresentNoCommittedEpoch` — no synthetic
    // epoch fabricated by Run 094/095/096 from normal-block commits.
    assert_eq!(
        storage.get_current_epoch().expect("read ok"),
        None,
        "no reconfig intent + only normal commits ⇒ storage must remain \
         PresentNoCommittedEpoch (Run 091/092 invariant preserved)"
    );
}

/// Negative: a `target_epoch = 0` intent — if reached the loop via a
/// bypass of the CLI gate — is refused by the engine's
/// `set_pending_reconfig_next_epoch` validation; the loop exits
/// fail-closed. This pins the second-layer defence: even if the CLI
/// gate were skipped by future code, the engine still refuses.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_096_zero_target_epoch_refused_by_engine_layer() {
    // We exercise the engine layer directly because the loop layer
    // accepts the config struct verbatim — the validation is in the
    // engine, which is the single canonical source of truth for the
    // monotonicity invariant.
    use qbind_consensus::validator_set::{ConsensusValidatorSet, ValidatorSetEntry};
    use qbind_consensus::{BasicHotStuffEngine, PendingReconfigIntentError};

    let v0 = ValidatorId::new(0);
    let entries = vec![ValidatorSetEntry {
        id: v0,
        voting_power: 1,
    }];
    let vset = ConsensusValidatorSet::new(entries).expect("valid");
    let mut engine: BasicHotStuffEngine<[u8; 32]> = BasicHotStuffEngine::new(v0, vset);

    let err = engine
        .set_pending_reconfig_next_epoch(0)
        .expect_err("target_epoch=0 must fail closed");
    assert!(matches!(err, PendingReconfigIntentError::TargetEpochZero));
}

// ============================================================================
// Tests — CLI gate (`derive_reconfig_proposal_from_cli_flag`)
// ============================================================================

/// No flag → no intent. The binary runs identically to pre-Run-096.
#[test]
fn run_096_cli_gate_default_is_none() {
    let out = derive_reconfig_proposal_from_cli_flag(None, false).expect("ok");
    assert_eq!(out, None);
    // Even on MainNet, the absent flag is `Ok(None)` (the gate must
    // never refuse a binary that didn't ask for reconfig).
    let out_main = derive_reconfig_proposal_from_cli_flag(None, true).expect("ok");
    assert_eq!(out_main, None);
}

/// `--devnet-reconfig-proposal-next-epoch=0` is refused at the CLI
/// gate, before the engine ever sees it.
#[test]
fn run_096_cli_gate_refuses_zero() {
    let err = derive_reconfig_proposal_from_cli_flag(Some(0), false)
        .expect_err("0 must fail closed");
    assert!(matches!(err, ReconfigProposalCliError::TargetEpochZero));
    // Display string must call out "fail-closed" so an operator can
    // grep the log line.
    let s = format!("{}", err);
    assert!(s.contains("Fail-closed"));
    assert!(s.contains("Run 096"));
}

/// MainNet binaries refuse the flag entirely. No governance path
/// authorizes operator-gated reconfig proposals on MainNet today.
#[test]
fn run_096_cli_gate_refuses_mainnet() {
    let err = derive_reconfig_proposal_from_cli_flag(Some(1), true)
        .expect_err("MainNet must fail closed");
    match err {
        ReconfigProposalCliError::MainnetRefused { target_epoch } => {
            assert_eq!(target_epoch, 1);
        }
        other => panic!("expected MainnetRefused, got {:?}", other),
    }
    let s = format!("{}", err);
    assert!(s.contains("MainNet"));
    assert!(s.contains("Fail-closed"));
}

/// On DevNet/TestNet a valid flag is converted into the canonical
/// `BinaryReconfigProposalConfig { target_epoch }` carrying exactly
/// the operator-supplied value — no derivation from
/// height/view/wall-clock.
#[test]
fn run_096_cli_gate_accepts_valid_devnet_flag() {
    let out = derive_reconfig_proposal_from_cli_flag(Some(7), false).expect("ok");
    assert_eq!(out, Some(BinaryReconfigProposalConfig { target_epoch: 7 }));
}