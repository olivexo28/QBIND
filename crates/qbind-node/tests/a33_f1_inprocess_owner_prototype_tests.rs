#![allow(dead_code)]

#[path = "support/a33_f1_inprocess_owner.rs"]
mod candidate;

use candidate::{
    EffectObservation, OwnerRole, Publication, RecordError, Refusal, SupervisorJoinError,
    WorkerStatus,
};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Barrier};

async fn ready_snapshot(reader: &candidate::StateReader) -> candidate::Snapshot {
    reader
        .wait_for(|state| state.worker_completed)
        .await
        .expect("worker completion observed before watchdog")
}

#[tokio::test]
async fn handoff_requires_acceptance_and_lost_initiator_cannot_admit() {
    let (release, wait) = oneshot::channel::<()>();
    let (owner, supervisor_task) = candidate::spawn_operation(8, 2, move |_| async move {
        let _ = wait.await;
        EffectObservation::Known(7)
    });
    let reader = owner.reader();
    let (handoff_tx, mut handoff_rx) = mpsc::channel(1);
    let initiator_task = tokio::spawn(async move { owner.offer_handoff(&handoff_tx).await });
    let offer = tokio::time::timeout(candidate::WATCHDOG, handoff_rx.recv())
        .await
        .expect("offer watchdog")
        .expect("handoff offer");

    assert_eq!(reader.snapshot().await.owner, OwnerRole::Initiator);
    drop(offer);
    initiator_task.abort();
    assert!(matches!(
        initiator_task.await,
        Err(error) if error.is_cancelled()
    ));
    let lost = reader
        .wait_for(|state| state.owner == OwnerRole::Lost)
        .await
        .expect("owner-loss transition observed");
    assert!(lost.refusal_closed);
    assert!(!lost.participation_allowed);
    assert_eq!(
        lost.refuse(OwnerRole::Supervisor),
        Err(Refusal::NotCurrentOwner)
    );
    assert_eq!(lost.protected_admissions, 0);

    let _ = release.send(());
    let _ = reader
        .wait_for(|state| state.worker_completed)
        .await
        .expect("worker completion observed");
    drop(reader);
    assert!(supervisor_task.join().await.is_ok());
}

#[tokio::test]
async fn accepted_handoff_survives_initiator_completion_and_allows_live_operation() {
    let (release, wait) = oneshot::channel::<()>();
    let (owner, supervisor_task) = candidate::spawn_operation(8, 4, move |publisher| async move {
        publisher.observe(Publication::Visible).await.unwrap();
        publisher.observe(Publication::Acknowledged).await.unwrap();
        let _ = wait.await;
        EffectObservation::Known(11)
    });
    let reader = owner.reader();
    let (handoff_tx, mut handoff_rx) = mpsc::channel(1);
    let initiator_task = tokio::spawn(async move { owner.offer_handoff(&handoff_tx).await });
    let offer = tokio::time::timeout(candidate::WATCHDOG, handoff_rx.recv())
        .await
        .expect("offer watchdog")
        .expect("handoff offer");
    let supervisor_owner = offer.accept().await.unwrap();
    assert_eq!(initiator_task.await.unwrap(), Ok(()));
    let transferred = reader.snapshot().await;
    assert_eq!(transferred.owner, OwnerRole::Supervisor);
    assert!(!transferred.operation_cancelled);

    let _ = release.send(());
    let completed = ready_snapshot(&reader).await;
    assert_eq!(completed.worker_status, WorkerStatus::Completed);
    assert!(supervisor_owner.admit_protected_operation().await.is_ok());
    assert!(supervisor_owner.admit_protected_operation().await.is_ok());
    assert_eq!(
        reader.snapshot().await.protected_admissions,
        2,
        "the live-operation model does not impose a one-mutation limit"
    );

    supervisor_owner.retire().await.unwrap();
    assert_eq!(
        supervisor_owner.admit_protected_operation().await,
        Err(Refusal::OperationRetired)
    );
    drop(supervisor_owner);
    drop(reader);
    assert!(supervisor_task.join().await.is_ok());
}

#[tokio::test]
async fn operation_cancellation_is_observed_and_never_reopens_admission() {
    let (_release, wait) = oneshot::channel::<()>();
    let (owner, supervisor_task) = candidate::spawn_operation(8, 3, move |_| async move {
        let _ = wait.await;
        EffectObservation::Known(3)
    });
    let reader = owner.reader();
    let (handoff_tx, mut handoff_rx) = mpsc::channel(1);
    let initiator_task = tokio::spawn(async move { owner.offer_handoff(&handoff_tx).await });
    let offer = tokio::time::timeout(candidate::WATCHDOG, handoff_rx.recv())
        .await
        .expect("offer watchdog")
        .expect("handoff offer");
    let supervisor_owner = offer.accept().await.unwrap();
    assert_eq!(initiator_task.await.unwrap(), Ok(()));
    supervisor_owner.cancel_operation().await.unwrap();
    let cancelled = reader
        .wait_for(|state| state.worker_status == WorkerStatus::Cancelled)
        .await
        .expect("cancelled worker join observed");
    assert!(cancelled.operation_cancelled);
    assert!(cancelled.worker_completed);
    assert!(cancelled.outcome_unknown);
    assert_eq!(
        supervisor_owner.admit_protected_operation().await,
        Err(Refusal::OperationCancelled)
    );
    drop(supervisor_owner);
    drop(reader);
    assert!(supervisor_task.join().await.is_ok());
}

#[tokio::test]
async fn worker_panic_is_observed_as_unknown_and_blocks_admission() {
    let (owner, supervisor_task) =
        candidate::spawn_operation(8, 2, |_| async move { panic!("synthetic worker panic") });
    let reader = owner.reader();
    let panicked = reader
        .wait_for(|state| state.worker_status == WorkerStatus::Panicked)
        .await
        .expect("panic join observed");
    assert!(panicked.worker_completed);
    assert!(panicked.outcome_unknown);
    assert_eq!(
        owner.admit_protected_operation().await,
        Err(Refusal::PublicationNotAcknowledged)
    );
    drop(owner);
    drop(reader);
    assert!(supervisor_task.join().await.is_ok());
}

#[tokio::test]
async fn failed_and_uncertain_publication_cannot_be_overwritten() {
    let (owner, supervisor_task) = candidate::spawn_operation(8, 4, |publisher| async move {
        assert!(publisher.observe(Publication::Failed).await.is_ok());
        assert!(matches!(
            publisher.observe(Publication::Acknowledged).await,
            Err(candidate::PublishError::InvalidTransition(
                Publication::Acknowledged
            ))
        ));
        assert!(publisher.observe(Publication::Uncertain).await.is_err());
        EffectObservation::Unknown
    });
    let reader = owner.reader();
    let failed = ready_snapshot(&reader).await;
    assert_eq!(failed.publication, Publication::Failed);
    assert!(failed.outcome_unknown);

    let (owner2, supervisor_task2) = candidate::spawn_operation(8, 4, |publisher| async move {
        publisher.observe(Publication::Uncertain).await.unwrap();
        assert!(publisher.observe(Publication::Failed).await.is_err());
        assert!(publisher.observe(Publication::Acknowledged).await.is_err());
        EffectObservation::Unknown
    });
    let reader2 = owner2.reader();
    let uncertain = ready_snapshot(&reader2).await;
    assert_eq!(uncertain.publication, Publication::Uncertain);
    assert!(uncertain.outcome_unknown);

    drop(owner);
    drop(reader);
    drop(owner2);
    drop(reader2);
    assert!(supervisor_task.join().await.is_ok());
    assert!(supervisor_task2.join().await.is_ok());
}

#[tokio::test]
async fn late_unknown_conflict_and_capacity_refusal_remain_closed() {
    let (owner, supervisor_task) = candidate::spawn_operation(8, 3, |publisher| async move {
        publisher.observe(Publication::Visible).await.unwrap();
        publisher.observe(Publication::Acknowledged).await.unwrap();
        EffectObservation::Known(5)
    });
    let reader = owner.reader();
    let completed = ready_snapshot(&reader).await;
    assert_eq!(completed.publication, Publication::Acknowledged);
    assert!(owner.admit_protected_operation().await.is_ok());

    owner
        .record_outcome(EffectObservation::Unknown)
        .await
        .unwrap();
    assert_eq!(
        owner.admit_protected_operation().await,
        Err(Refusal::EffectUnresolved)
    );
    owner
        .record_outcome(EffectObservation::Known(6))
        .await
        .unwrap();
    assert!(reader.snapshot().await.outcome_conflict);
    assert_eq!(
        owner.admit_protected_operation().await,
        Err(Refusal::EffectUnresolved)
    );
    drop(owner);
    drop(reader);
    assert!(supervisor_task.join().await.is_ok());

    let (owner, supervisor_task) = candidate::spawn_operation(8, 1, |publisher| async move {
        publisher.observe(Publication::Visible).await.unwrap();
        publisher.observe(Publication::Acknowledged).await.unwrap();
        EffectObservation::Known(8)
    });
    let reader = owner.reader();
    let _ = ready_snapshot(&reader).await;
    assert!(matches!(
        owner.record_outcome(EffectObservation::Unknown).await,
        Err(RecordError::Capacity(EffectObservation::Unknown))
    ));
    assert_eq!(
        owner.admit_protected_operation().await,
        Err(Refusal::CapacityUncertain)
    );
    drop(owner);
    drop(reader);
    assert!(supervisor_task.join().await.is_ok());
}

#[tokio::test]
async fn coordinator_abort_is_joined_and_marks_supervisor_lost() {
    let (owner, supervisor_task) = candidate::spawn_operation(8, 2, |publisher| async move {
        publisher.observe(Publication::Visible).await.unwrap();
        publisher.observe(Publication::Acknowledged).await.unwrap();
        EffectObservation::Known(9)
    });
    let reader = owner.reader();
    let _ = ready_snapshot(&reader).await;
    assert!(matches!(
        supervisor_task.abort_and_join().await,
        Err(SupervisorJoinError::Task(error)) if error.is_cancelled()
    ));
    assert!(reader.snapshot().await.supervisor_lost);
    assert_eq!(
        owner.admit_protected_operation().await,
        Err(Refusal::SupervisorLost)
    );
    drop(owner);
    drop(reader);
}

#[tokio::test]
async fn coordinator_panic_is_joined_and_marks_supervisor_lost() {
    let (owner, supervisor_task) = candidate::spawn_operation(8, 2, |publisher| async move {
        publisher.observe(Publication::Visible).await.unwrap();
        publisher.observe(Publication::Acknowledged).await.unwrap();
        EffectObservation::Known(10)
    });
    let reader = owner.reader();
    let _ = ready_snapshot(&reader).await;
    owner.panic_supervisor_for_test().await;
    assert!(matches!(
        supervisor_task.join().await,
        Err(SupervisorJoinError::Task(error)) if error.is_panic()
    ));
    assert!(reader.snapshot().await.supervisor_lost);
    assert_eq!(
        owner.admit_protected_operation().await,
        Err(Refusal::SupervisorLost)
    );
    drop(owner);
    drop(reader);
}

#[tokio::test]
async fn full_command_queue_refuses_admission_without_mutation() {
    let (owner, supervisor_task) =
        candidate::spawn_operation(1, 2, |_| async move { EffectObservation::Known(17) });
    let owner = Arc::new(owner);
    let state_guard = owner.hold_state_for_test().await;
    let barrier = Arc::new(Barrier::new(4));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..3 {
        let owner = owner.clone();
        let barrier = barrier.clone();
        tasks.spawn(async move {
            barrier.wait().await;
            owner.admit_protected_operation().await
        });
    }
    barrier.wait().await;
    let first = tokio::time::timeout(candidate::WATCHDOG, tasks.join_next())
        .await
        .expect("capacity refusal watchdog")
        .expect("capacity refusal task")
        .expect("capacity refusal task joined");
    assert_eq!(first, Err(Refusal::CapacityUncertain));
    drop(state_guard);
    while let Some(result) = tokio::time::timeout(candidate::WATCHDOG, tasks.join_next())
        .await
        .expect("remaining admission tasks watchdog")
    {
        assert_eq!(
            result.expect("admission task joined"),
            Err(Refusal::CapacityUncertain)
        );
    }
    assert_eq!(owner.reader().snapshot().await.protected_admissions, 0);
    drop(owner);
    assert!(supervisor_task.join().await.is_ok());
}

#[tokio::test]
async fn sensitivity_checks_reject_premature_handoff_unobserved_work_and_reopening() {
    let (owner, supervisor_task) = candidate::spawn_operation(8, 3, |publisher| async move {
        publisher.observe(Publication::Visible).await.unwrap();
        publisher.observe(Publication::Acknowledged).await.unwrap();
        EffectObservation::Known(13)
    });
    let reader = owner.reader();
    let before_accept = ready_snapshot(&reader).await;
    assert_eq!(before_accept.owner, OwnerRole::Initiator);

    let mut premature_handoff_defect = before_accept.clone();
    premature_handoff_defect.owner = OwnerRole::Supervisor;
    let handoff_invariant = |state: &candidate::Snapshot| {
        if state.owner == OwnerRole::Supervisor {
            Err("receiver owner appeared before explicit acceptance")
        } else {
            Ok(())
        }
    };
    assert_eq!(handoff_invariant(&before_accept), Ok(()));
    assert_eq!(
        handoff_invariant(&premature_handoff_defect),
        Err("receiver owner appeared before explicit acceptance")
    );

    let mut unobserved = before_accept.clone();
    unobserved.worker_completed = false;
    assert_eq!(
        unobserved.refuse(OwnerRole::Initiator),
        Err(Refusal::WorkerStillRunning)
    );

    let mut reopened = before_accept;
    reopened.refusal_closed = false;
    reopened.participation_allowed = true;
    assert_eq!(
        reopened.refuse(OwnerRole::Initiator),
        Err(Refusal::RefusalInvariant)
    );

    drop(owner);
    drop(reader);
    assert!(supervisor_task.join().await.is_ok());
}

#[tokio::test]
async fn cancellation_and_retirement_sensitivity_controls_reject_reopening() {
    let (cancelled_owner, cancelled_task) =
        candidate::spawn_operation(8, 2, |publisher| async move {
            publisher.observe(Publication::Visible).await.unwrap();
            publisher.observe(Publication::Acknowledged).await.unwrap();
            EffectObservation::Known(21)
        });
    let cancelled_reader = cancelled_owner.reader();
    let _ = ready_snapshot(&cancelled_reader).await;
    cancelled_owner.cancel_operation().await.unwrap();
    let cancelled = cancelled_reader.snapshot().await;
    assert!(cancelled.operation_cancelled);
    assert!(cancelled.refusal_closed);

    let mut cancelled_reopened = cancelled.clone();
    cancelled_reopened.refusal_closed = false;
    cancelled_reopened.participation_allowed = true;
    assert_eq!(
        cancelled_reopened.refuse(OwnerRole::Initiator),
        Err(Refusal::OperationCancelled)
    );
    drop(cancelled_owner);
    drop(cancelled_reader);
    assert!(cancelled_task.join().await.is_ok());

    let (retired_owner, retired_task) = candidate::spawn_operation(8, 2, |publisher| async move {
        publisher.observe(Publication::Visible).await.unwrap();
        publisher.observe(Publication::Acknowledged).await.unwrap();
        EffectObservation::Known(22)
    });
    let retired_reader = retired_owner.reader();
    let _ = ready_snapshot(&retired_reader).await;
    retired_owner.retire().await.unwrap();
    let retired = retired_reader.snapshot().await;
    assert!(retired.operation_retired);
    assert!(retired.refusal_closed);
    retired_owner
        .observe_publication(Publication::Uncertain)
        .await
        .unwrap();
    retired_owner
        .record_outcome(EffectObservation::Unknown)
        .await
        .unwrap();
    let late_retired = retired_reader.snapshot().await;
    assert!(late_retired.operation_retired);
    assert!(late_retired.refusal_closed);
    assert!(!late_retired.participation_allowed);
    assert_eq!(
        retired_owner.admit_protected_operation().await,
        Err(Refusal::OperationRetired)
    );

    let mut retired_reopened = late_retired;
    retired_reopened.refusal_closed = false;
    retired_reopened.participation_allowed = true;
    assert_eq!(
        retired_reopened.refuse(OwnerRole::Initiator),
        Err(Refusal::OperationRetired)
    );
    drop(retired_owner);
    drop(retired_reader);
    assert!(retired_task.join().await.is_ok());
}
