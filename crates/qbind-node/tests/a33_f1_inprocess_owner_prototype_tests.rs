#![allow(dead_code)]

#[path = "support/a33_f1_inprocess_owner.rs"]
mod candidate;

use candidate::{
    EffectObservation, HandoffError, OwnerRole, Publication, RecordError, Refusal,
    SupervisorJoinError, WorkerResultDisposition, WorkerStatus,
};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Barrier, Mutex as AsyncMutex};

async fn ready_snapshot(reader: &candidate::StateReader) -> candidate::Snapshot {
    reader
        .wait_for(|state| state.worker_completed)
        .await
        .expect("worker completion observed before watchdog")
}

#[derive(Debug, PartialEq, Eq)]
enum HandoffLifecycleError {
    UnexpectedlyAdmitted,
    UnexpectedRefusal(Refusal),
}

#[derive(Debug, PartialEq, Eq)]
enum WorkerBoundaryError {
    SupervisorLossNotRecorded,
    CoordinatorFutureDropNotObserved,
    CoordinatorJoinObservationMismatch,
    WorkerAbortNotRequested,
    WorkerJoinNotObserved,
    WorkerJoinUnexpectedlyObserved,
    WorkerResultNotMarkedUnobserved,
    WorkerResultDispositionMismatch {
        expected: WorkerResultDisposition,
        actual: WorkerResultDisposition,
    },
    WorkerReportedCompleted,
    AdmissionWaitTimedOut,
    SyntheticAdmissionAccepted,
    UnexpectedAdmissionRefusal(Refusal),
    AdmissionCounterChanged,
}

async fn check_worker_loss_before_observation_boundary(
    reader: &candidate::StateReader,
    owner: &candidate::OperationOwner,
    coordinator_join_observed: bool,
) -> Result<(), WorkerBoundaryError> {
    let before = reader.snapshot().await;
    let state_error = if !before.supervisor_lost {
        Some(WorkerBoundaryError::SupervisorLossNotRecorded)
    } else if !before.coordinator_future_dropped {
        Some(WorkerBoundaryError::CoordinatorFutureDropNotObserved)
    } else if before.coordinator_join_observed != coordinator_join_observed {
        Some(WorkerBoundaryError::CoordinatorJoinObservationMismatch)
    } else if !before.worker_abort_requested {
        Some(WorkerBoundaryError::WorkerAbortNotRequested)
    } else if before.worker_join_observed {
        Some(WorkerBoundaryError::WorkerJoinUnexpectedlyObserved)
    } else if !before.worker_result_unobserved {
        Some(WorkerBoundaryError::WorkerResultNotMarkedUnobserved)
    } else if before.worker_result_disposition != WorkerResultDisposition::NotObserved {
        Some(WorkerBoundaryError::WorkerResultDispositionMismatch {
            expected: WorkerResultDisposition::NotObserved,
            actual: before.worker_result_disposition,
        })
    } else if before.worker_completed || before.worker_status != WorkerStatus::Running {
        Some(WorkerBoundaryError::WorkerReportedCompleted)
    } else {
        None
    };

    match tokio::time::timeout(candidate::WATCHDOG, owner.admit_protected_operation()).await {
        Err(_) => return Err(WorkerBoundaryError::AdmissionWaitTimedOut),
        Ok(Err(Refusal::SupervisorLost)) => {}
        Ok(Err(reason)) => return Err(WorkerBoundaryError::UnexpectedAdmissionRefusal(reason)),
        Ok(Ok(())) => return Err(WorkerBoundaryError::SyntheticAdmissionAccepted),
    }
    if reader.snapshot().await.protected_admissions != before.protected_admissions {
        return Err(WorkerBoundaryError::AdmissionCounterChanged);
    }
    state_error.map_or(Ok(()), Err)
}

async fn check_observed_unrecorded_boundary(
    reader: &candidate::StateReader,
    owner: &candidate::OperationOwner,
) -> Result<(), WorkerBoundaryError> {
    let before = reader.snapshot().await;
    let state_error = if !before.supervisor_lost || !before.coordinator_future_dropped {
        Some(WorkerBoundaryError::SupervisorLossNotRecorded)
    } else if !before.coordinator_join_observed {
        Some(WorkerBoundaryError::CoordinatorJoinObservationMismatch)
    } else if !before.worker_join_observed {
        Some(WorkerBoundaryError::WorkerJoinNotObserved)
    } else if before.worker_result_unobserved {
        Some(WorkerBoundaryError::WorkerResultNotMarkedUnobserved)
    } else if before.worker_result_disposition != WorkerResultDisposition::ObservedUnrecorded {
        Some(WorkerBoundaryError::WorkerResultDispositionMismatch {
            expected: WorkerResultDisposition::ObservedUnrecorded,
            actual: before.worker_result_disposition,
        })
    } else if before.worker_completed || !before.observations.is_empty() {
        Some(WorkerBoundaryError::WorkerReportedCompleted)
    } else {
        None
    };

    match tokio::time::timeout(candidate::WATCHDOG, owner.admit_protected_operation()).await {
        Err(_) => return Err(WorkerBoundaryError::AdmissionWaitTimedOut),
        Ok(Err(Refusal::SupervisorLost)) => {}
        Ok(Err(reason)) => return Err(WorkerBoundaryError::UnexpectedAdmissionRefusal(reason)),
        Ok(Ok(())) => return Err(WorkerBoundaryError::SyntheticAdmissionAccepted),
    }
    if reader.snapshot().await.protected_admissions != before.protected_admissions {
        return Err(WorkerBoundaryError::AdmissionCounterChanged);
    }
    state_error.map_or(Ok(()), Err)
}

fn require_join_observer(supervisor: &candidate::SupervisorTask) -> Result<(), &'static str> {
    if supervisor.join_observation_is_owned_for_test() {
        Ok(())
    } else {
        Err("coordinator JoinHandle has no retained observer")
    }
}

async fn require_no_supervisor_admission(
    reader: &candidate::StateReader,
) -> Result<(), HandoffLifecycleError> {
    match reader.admit_as(OwnerRole::Supervisor).await {
        Err(Refusal::NotCurrentOwner) => Ok(()),
        Err(reason) => Err(HandoffLifecycleError::UnexpectedRefusal(reason)),
        Ok(()) => Err(HandoffLifecycleError::UnexpectedlyAdmitted),
    }
}

#[tokio::test]
async fn handoff_requires_acceptance_and_lost_initiator_cannot_admit() {
    let (release, wait) = oneshot::channel::<()>();
    let (owner, mut supervisor_task) = candidate::spawn_operation(8, 2, move |_| async move {
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
async fn receiver_cancelled_after_acceptance_reply_loses_guarded_ownership() {
    let (owner, mut supervisor_task) = candidate::spawn_operation(8, 3, |publisher| async move {
        publisher.observe(Publication::Visible).await.unwrap();
        publisher.observe(Publication::Acknowledged).await.unwrap();
        EffectObservation::Known(31)
    });
    let reader = owner.reader();
    let (handoff_tx, mut handoff_rx) = mpsc::channel(1);
    let initiator_task = tokio::spawn(async move { owner.offer_handoff(&handoff_tx).await });
    let offer = tokio::time::timeout(candidate::WATCHDOG, handoff_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let (request_sent_tx, request_sent_rx) = oneshot::channel();
    let (reply_sent_tx, reply_sent_rx) = oneshot::channel();
    let (continue_tx, continue_rx) = oneshot::channel();
    let receiver_task = tokio::spawn(async move {
        offer
            .accept_paused_for_test(request_sent_tx, reply_sent_tx, continue_rx)
            .await
    });

    tokio::time::timeout(candidate::WATCHDOG, request_sent_rx)
        .await
        .expect("acceptance request sent")
        .expect("request signal");
    tokio::time::timeout(candidate::WATCHDOG, reply_sent_rx)
        .await
        .expect("coordinator sent acceptance reply")
        .expect("reply signal");
    assert_eq!(
        tokio::time::timeout(candidate::WATCHDOG, initiator_task)
            .await
            .expect("initiator acknowledgment")
            .expect("initiator task joined"),
        Ok(())
    );

    receiver_task.abort();
    assert!(matches!(
        receiver_task.await,
        Err(error) if error.is_cancelled()
    ));
    let lost = reader
        .wait_for(|state| state.owner == OwnerRole::Lost)
        .await
        .expect("drop guard loss recorded");
    assert!(lost.refusal_closed);
    assert_eq!(require_no_supervisor_admission(&reader).await, Ok(()));

    drop(reader);
    assert!(supervisor_task.join().await.is_ok());
    let _ = continue_tx;
}

#[tokio::test]
async fn handoff_delivery_failure_and_acquired_handle_loss_are_closed() {
    let (owner, mut supervisor_task) = candidate::spawn_operation(8, 3, |publisher| async move {
        publisher.observe(Publication::Visible).await.unwrap();
        publisher.observe(Publication::Acknowledged).await.unwrap();
        EffectObservation::Known(32)
    });
    let reader = owner.reader();
    let (closed_tx, closed_rx) = mpsc::channel(1);
    drop(closed_rx);
    assert!(matches!(
        owner.offer_handoff(&closed_tx).await,
        Err(HandoffError::ReceiverUnavailable)
    ));
    reader
        .wait_for(|state| state.owner == OwnerRole::Lost)
        .await
        .expect("failed delivery loses initiating responsibility");
    assert_eq!(require_no_supervisor_admission(&reader).await, Ok(()));
    drop(reader);
    assert!(supervisor_task.join().await.is_ok());

    let (owner, mut supervisor_task) = candidate::spawn_operation(8, 3, |publisher| async move {
        publisher.observe(Publication::Visible).await.unwrap();
        publisher.observe(Publication::Acknowledged).await.unwrap();
        EffectObservation::Known(33)
    });
    let reader = owner.reader();
    let (handoff_tx, mut handoff_rx) = mpsc::channel(1);
    let initiator_task = tokio::spawn(async move { owner.offer_handoff(&handoff_tx).await });
    let offer = tokio::time::timeout(candidate::WATCHDOG, handoff_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let supervisor_owner = offer.accept().await.unwrap();
    assert_eq!(initiator_task.await.unwrap(), Ok(()));
    drop(supervisor_owner);
    reader
        .wait_for(|state| state.owner == OwnerRole::Lost)
        .await
        .expect("acquired handle drop reports ownership loss");
    assert_eq!(require_no_supervisor_admission(&reader).await, Ok(()));
    drop(reader);
    assert!(supervisor_task.join().await.is_ok());
}

#[tokio::test]
async fn full_control_queue_still_records_handoff_owner_loss_synchronously() {
    let (owner, mut supervisor_task) =
        candidate::spawn_operation(1, 2, |_| async move { EffectObservation::Known(35) });
    let reader = owner.reader();
    let (handoff_tx, mut handoff_rx) = mpsc::channel(1);
    let initiator_task = tokio::spawn(async move { owner.offer_handoff(&handoff_tx).await });
    let offer = tokio::time::timeout(candidate::WATCHDOG, handoff_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let supervisor_owner = offer.accept().await.unwrap();
    assert_eq!(initiator_task.await.unwrap(), Ok(()));

    let (coordinator_entered, release_coordinator) =
        supervisor_owner.pause_coordinator_for_test().await;
    coordinator_entered.await.unwrap();
    reader
        .fill_command_queue_for_test()
        .expect("one command fills the bounded control channel");
    drop(supervisor_owner);

    let lost = reader.snapshot().await;
    assert_eq!(lost.owner, OwnerRole::Lost);
    assert!(lost.control_overflow);
    assert!(lost.refusal_closed);
    assert_eq!(
        lost.refuse(OwnerRole::Supervisor),
        Err(Refusal::CapacityUncertain)
    );
    let _ = release_coordinator.send(());
    assert_eq!(
        reader.admit_as(OwnerRole::Supervisor).await,
        Err(Refusal::CapacityUncertain)
    );
    drop(reader);
    assert!(supervisor_task.join().await.is_ok());
}

#[tokio::test]
async fn omitted_handoff_loss_guard_is_detected_by_same_lifecycle_check() {
    let (owner, mut supervisor_task) = candidate::spawn_operation(8, 3, |publisher| async move {
        publisher.observe(Publication::Visible).await.unwrap();
        publisher.observe(Publication::Acknowledged).await.unwrap();
        EffectObservation::Known(34)
    });
    let reader = owner.reader();
    let (handoff_tx, mut handoff_rx) = mpsc::channel(1);
    let initiator_task = tokio::spawn(async move { owner.offer_handoff(&handoff_tx).await });
    let offer = tokio::time::timeout(candidate::WATCHDOG, handoff_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let (request_sent_tx, request_sent_rx) = oneshot::channel();
    let (reply_sent_tx, reply_sent_rx) = oneshot::channel();
    let (continue_tx, continue_rx) = oneshot::channel();
    let receiver_task = tokio::spawn(async move {
        offer
            .accept_without_loss_guard_for_test(request_sent_tx, reply_sent_tx, continue_rx)
            .await
    });
    request_sent_rx.await.unwrap();
    reply_sent_rx.await.unwrap();
    assert_eq!(initiator_task.await.unwrap(), Ok(()));
    receiver_task.abort();
    assert!(matches!(
        receiver_task.await,
        Err(error) if error.is_cancelled()
    ));

    let defect = require_no_supervisor_admission(&reader).await;
    assert_eq!(defect, Err(HandoffLifecycleError::UnexpectedlyAdmitted));
    reader.mark_owner_lost_for_test(OwnerRole::Supervisor).await;
    reader
        .wait_for(|state| state.owner == OwnerRole::Lost)
        .await
        .expect("sensitivity fixture cleanup recorded");
    drop(reader);
    assert!(supervisor_task.join().await.is_ok());
    let _ = continue_tx;
}

#[tokio::test]
async fn accepted_handoff_survives_initiator_completion_and_allows_live_operation() {
    let (release, wait) = oneshot::channel::<()>();
    let (owner, mut supervisor_task) =
        candidate::spawn_operation(8, 4, move |publisher| async move {
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
    let (owner, mut supervisor_task) = candidate::spawn_operation(8, 3, move |_| async move {
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
    let (owner, mut supervisor_task) =
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
    let (owner, mut supervisor_task) = candidate::spawn_operation(8, 4, |publisher| async move {
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

    let (owner2, mut supervisor_task2) = candidate::spawn_operation(8, 4, |publisher| async move {
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
    let (owner, mut supervisor_task) = candidate::spawn_operation(8, 3, |publisher| async move {
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

    let (owner, mut supervisor_task) = candidate::spawn_operation(8, 1, |publisher| async move {
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
    let (owner, mut supervisor_task) = candidate::spawn_operation(8, 2, |publisher| async move {
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
async fn coordinator_abort_before_first_poll_drops_preinstalled_worker_guard() {
    let (owner, mut supervisor_task, _result_ready, _release_result, worker_dropped) =
        candidate::spawn_operation_with_result_gate_for_test(8, 2, |_| async {
            EffectObservation::Known(60)
        });
    let reader = owner.reader();

    let before_poll = reader.snapshot().await;
    assert!(!before_poll.coordinator_future_polled);
    assert!(!before_poll.coordinator_future_dropped);
    assert!(!before_poll.worker_future_entered);
    assert_eq!(
        before_poll.worker_result_disposition,
        WorkerResultDisposition::Pending
    );

    assert!(matches!(
        supervisor_task.abort_and_join().await,
        Err(SupervisorJoinError::Task(error)) if error.is_cancelled()
    ));
    let destroyed = reader.snapshot().await;
    assert!(destroyed.coordinator_future_dropped);
    assert!(!destroyed.coordinator_future_polled);
    assert!(destroyed.coordinator_abort_requested);
    assert!(destroyed.coordinator_join_observed);
    assert!(destroyed.worker_abort_requested);
    assert!(!destroyed.worker_join_observed);
    assert!(destroyed.worker_result_unobserved);
    assert_eq!(
        destroyed.worker_result_disposition,
        WorkerResultDisposition::NotObserved
    );
    assert!(!destroyed.worker_completed);
    assert_eq!(destroyed.observations, Vec::new());

    let drop_signal = tokio::time::timeout(candidate::WATCHDOG, worker_dropped).await;
    if destroyed.worker_future_entered {
        drop_signal
            .expect("entered worker drop notification watchdog")
            .expect("entered worker future drop notification");
    } else if let Ok(result) = drop_signal {
        result.expect("pre-poll worker future drop notification");
    }

    assert_eq!(
        check_worker_loss_before_observation_boundary(&reader, &owner, true).await,
        Ok(())
    );
    drop(owner);
    drop(reader);
}

#[tokio::test]
async fn omitted_pre_poll_worker_guard_is_rejected_by_loss_phase_checker() {
    let (owner, mut supervisor_task, _result_ready, _release_result, worker_dropped) =
        candidate::spawn_operation_without_early_worker_guard_for_test(8, 2, |_| async {
            EffectObservation::Known(601)
        });
    let reader = owner.reader();
    assert!(!reader.snapshot().await.coordinator_future_polled);

    assert!(matches!(
        supervisor_task.abort_and_join().await,
        Err(SupervisorJoinError::Task(error)) if error.is_cancelled()
    ));
    let state = reader.snapshot().await;
    assert!(state.coordinator_future_dropped);
    assert!(!state.coordinator_future_polled);
    assert!(!state.worker_abort_requested);
    assert!(!state.worker_join_observed);
    assert!(!state.worker_result_unobserved);
    assert_eq!(
        state.worker_result_disposition,
        WorkerResultDisposition::Pending
    );
    assert_eq!(
        check_worker_loss_before_observation_boundary(&reader, &owner, true).await,
        Err(WorkerBoundaryError::WorkerAbortNotRequested),
        "the same phase checker rejects the missing pre-poll guard"
    );

    supervisor_task.abort_worker_without_observer_for_test();
    tokio::time::timeout(candidate::WATCHDOG, worker_dropped)
        .await
        .expect("sensitivity worker future drop watchdog")
        .expect("sensitivity worker future drop signal");
    assert!(
        !reader.snapshot().await.worker_join_observed,
        "the test-only cleanup abort does not manufacture JoinHandle observation"
    );
    drop(owner);
    drop(reader);
}

#[tokio::test]
async fn coordinator_abort_with_worker_pending_before_effect_leaves_result_unobserved() {
    let (worker_entered_tx, worker_entered_rx) = oneshot::channel();
    let (_release_worker_tx, release_worker_rx) = oneshot::channel::<()>();
    let (owner, mut supervisor_task, _result_ready, _release_result, worker_dropped) =
        candidate::spawn_operation_with_result_gate_for_test(8, 2, move |_| async move {
            let _ = worker_entered_tx.send(());
            let _ = release_worker_rx.await;
            EffectObservation::Known(61)
        });
    let reader = owner.reader();
    tokio::time::timeout(candidate::WATCHDOG, worker_entered_rx)
        .await
        .expect("worker entered before synthetic effect")
        .expect("worker-entry signal");
    assert_eq!(
        reader.snapshot().await.publication,
        Publication::Pending,
        "no synthetic publication was admitted before coordinator loss"
    );

    assert!(matches!(
        supervisor_task.abort_and_join().await,
        Err(SupervisorJoinError::Task(error)) if error.is_cancelled()
    ));
    tokio::time::timeout(candidate::WATCHDOG, worker_dropped)
        .await
        .expect("cancelled worker future dropped")
        .expect("worker future drop signal");

    let state = reader.snapshot().await;
    assert!(state.coordinator_abort_requested);
    assert!(state.coordinator_join_observed);
    assert!(state.worker_abort_requested);
    assert!(!state.worker_join_observed);
    assert!(state.worker_result_unobserved);
    assert!(!state.worker_completed);
    assert_eq!(state.worker_status, WorkerStatus::Running);
    assert_eq!(state.publication, Publication::Pending);
    assert!(!state.outcome_unknown, "no worker result was recorded");
    assert_eq!(
        check_worker_loss_before_observation_boundary(&reader, &owner, true).await,
        Ok(())
    );

    drop(owner);
    drop(reader);
}

#[tokio::test]
async fn coordinator_panic_after_synthetic_effect_discards_unobserved_worker_result() {
    let (owner, mut supervisor_task, result_ready, _release_result, worker_dropped) =
        candidate::spawn_operation_with_result_gate_for_test(8, 3, |publisher| async move {
            publisher.observe(Publication::Visible).await.unwrap();
            publisher.observe(Publication::Acknowledged).await.unwrap();
            EffectObservation::Known(62)
        });
    let reader = owner.reader();
    reader
        .wait_for(|state| state.publication == Publication::Acknowledged)
        .await
        .expect("synthetic effect admitted and acknowledged");
    tokio::time::timeout(candidate::WATCHDOG, result_ready)
        .await
        .expect("worker body produced a result held behind the test gate")
        .expect("worker-result-ready signal");
    assert!(!reader.snapshot().await.worker_join_observed);

    owner.panic_supervisor_for_test().await;
    assert!(matches!(
        supervisor_task.join().await,
        Err(SupervisorJoinError::Task(error)) if error.is_panic()
    ));
    tokio::time::timeout(candidate::WATCHDOG, worker_dropped)
        .await
        .expect("worker future dropped with its held result unavailable")
        .expect("worker future drop signal");

    let state = reader.snapshot().await;
    assert_eq!(state.publication, Publication::Acknowledged);
    assert!(state.coordinator_join_observed);
    assert!(!state.worker_join_observed);
    assert!(state.worker_result_unobserved);
    assert!(!state.worker_completed);
    assert_eq!(state.worker_status, WorkerStatus::Running);
    assert!(state.observations.is_empty());
    assert!(!state.outcome_unknown);
    assert_eq!(
        check_worker_loss_before_observation_boundary(&reader, &owner, true).await,
        Ok(())
    );

    drop(owner);
    drop(reader);
}

#[tokio::test]
async fn dropping_outer_coordinator_guard_requests_cleanup_but_leaves_join_unobserved() {
    let (worker_entered_tx, worker_entered_rx) = oneshot::channel();
    let (_release_worker_tx, release_worker_rx) = oneshot::channel::<()>();
    let (owner, supervisor_task, _result_ready, _release_result, worker_dropped) =
        candidate::spawn_operation_with_result_gate_for_test(8, 2, move |_| async move {
            let _ = worker_entered_tx.send(());
            let _ = release_worker_rx.await;
            EffectObservation::Known(63)
        });
    let reader = owner.reader();
    tokio::time::timeout(candidate::WATCHDOG, worker_entered_rx)
        .await
        .expect("worker pending before synthetic effect")
        .expect("worker-entry signal");

    drop(supervisor_task);
    tokio::time::timeout(
        candidate::WATCHDOG,
        reader.wait_for(|state| state.coordinator_future_dropped),
    )
    .await
    .expect("coordinator future-drop watchdog")
    .expect("coordinator future drop observed by test instrumentation");
    tokio::time::timeout(candidate::WATCHDOG, worker_dropped)
        .await
        .expect("worker abort cleanup requested")
        .expect("worker future drop signal");

    let state = reader.snapshot().await;
    assert!(state.coordinator_abort_requested);
    assert!(!state.coordinator_join_observed);
    assert!(state.worker_abort_requested);
    assert!(!state.worker_join_observed);
    assert!(state.worker_result_unobserved);
    assert!(!state.worker_completed);
    assert_eq!(state.worker_status, WorkerStatus::Running);
    assert_eq!(state.publication, Publication::Pending);
    assert!(!state.outcome_unknown);
    assert_eq!(
        check_worker_loss_before_observation_boundary(&reader, &owner, false).await,
        Ok(())
    );

    drop(owner);
    drop(reader);
}

#[tokio::test]
async fn abandoned_worker_sensitivity_detects_missing_unobserved_result_marker() {
    let (worker_entered_tx, worker_entered_rx) = oneshot::channel();
    let (_release_worker_tx, release_worker_rx) = oneshot::channel::<()>();
    let (owner, mut supervisor_task, _result_ready, _release_result, worker_dropped) =
        candidate::spawn_operation_with_result_gate_for_test(8, 2, move |_| async move {
            let _ = worker_entered_tx.send(());
            let _ = release_worker_rx.await;
            EffectObservation::Known(64)
        });
    let reader = owner.reader();
    tokio::time::timeout(candidate::WATCHDOG, worker_entered_rx)
        .await
        .expect("worker entered")
        .expect("worker-entry signal");
    assert!(matches!(
        supervisor_task.abort_and_join().await,
        Err(SupervisorJoinError::Task(error)) if error.is_cancelled()
    ));
    tokio::time::timeout(candidate::WATCHDOG, worker_dropped)
        .await
        .expect("worker cancellation observed")
        .expect("worker future drop signal");
    assert_eq!(
        check_worker_loss_before_observation_boundary(&reader, &owner, true).await,
        Ok(()),
        "the documented shutdown trace passes the common boundary checker"
    );

    reader.clear_worker_result_unobserved_for_test();
    assert_eq!(
        check_worker_loss_before_observation_boundary(&reader, &owner, true).await,
        Err(WorkerBoundaryError::WorkerResultNotMarkedUnobserved),
        "the same checker detects omission of the unresolved-result marker"
    );
    drop(owner);
    drop(reader);
}

#[tokio::test]
async fn coordinator_loss_after_worker_join_keeps_result_observed_but_unrecorded() {
    let (owner, mut supervisor_task, result_observed, _release_application) =
        candidate::spawn_operation_with_join_apply_gate_for_test(8, 2, |_| async {
            EffectObservation::Known(66)
        });
    let reader = owner.reader();
    tokio::time::timeout(candidate::WATCHDOG, result_observed)
        .await
        .expect("coordinator obtained the worker JoinHandle result")
        .expect("worker-result-observed barrier signal");

    let paused = reader.snapshot().await;
    assert!(paused.coordinator_future_polled);
    assert!(!paused.coordinator_future_dropped);
    assert!(paused.worker_join_observed);
    assert!(!paused.worker_result_unobserved);
    assert_eq!(
        paused.worker_result_disposition,
        WorkerResultDisposition::ObservedUnrecorded
    );
    assert!(!paused.worker_completed);
    assert!(paused.observations.is_empty());

    assert!(matches!(
        supervisor_task.abort_and_join().await,
        Err(SupervisorJoinError::Task(error)) if error.is_cancelled()
    ));
    let lost = reader.snapshot().await;
    assert!(lost.coordinator_future_dropped);
    assert!(lost.coordinator_join_observed);
    assert!(lost.worker_join_observed);
    assert!(!lost.worker_result_unobserved);
    assert_eq!(
        lost.worker_result_disposition,
        WorkerResultDisposition::ObservedUnrecorded
    );
    assert!(!lost.worker_completed);
    assert!(lost.observations.is_empty());
    assert_eq!(
        check_observed_unrecorded_boundary(&reader, &owner).await,
        Ok(())
    );
    drop(owner);
    drop(reader);
}

#[tokio::test]
async fn false_recorded_classification_is_rejected_by_result_phase_checker() {
    let (owner, mut supervisor_task, result_observed, _release_application) =
        candidate::spawn_operation_with_join_apply_gate_for_test(8, 2, |_| async {
            EffectObservation::Known(67)
        });
    let reader = owner.reader();
    tokio::time::timeout(candidate::WATCHDOG, result_observed)
        .await
        .expect("worker join result reached application barrier")
        .expect("worker-result-observed barrier signal");

    assert!(matches!(
        supervisor_task.abort_and_join().await,
        Err(SupervisorJoinError::Task(error)) if error.is_cancelled()
    ));
    reader.classify_worker_result_for_sensitivity_test(WorkerResultDisposition::Recorded);
    assert_eq!(
        check_observed_unrecorded_boundary(&reader, &owner).await,
        Err(WorkerBoundaryError::WorkerResultDispositionMismatch {
            expected: WorkerResultDisposition::ObservedUnrecorded,
            actual: WorkerResultDisposition::Recorded,
        }),
        "the same phase checker rejects a false available/recorded classification"
    );

    drop(owner);
    drop(reader);
}

#[tokio::test]
async fn normal_worker_and_coordinator_results_are_both_observed() {
    let (owner, mut supervisor_task, result_ready, release_result, worker_dropped) =
        candidate::spawn_operation_with_result_gate_for_test(8, 3, |publisher| async move {
            publisher.observe(Publication::Visible).await.unwrap();
            publisher.observe(Publication::Acknowledged).await.unwrap();
            EffectObservation::Known(65)
        });
    let reader = owner.reader();
    tokio::time::timeout(
        candidate::WATCHDOG,
        reader.wait_for(|state| state.publication == Publication::Acknowledged),
    )
    .await
    .expect("publication acknowledgment watchdog")
    .expect("synthetic publication acknowledged");
    tokio::time::timeout(candidate::WATCHDOG, result_ready)
        .await
        .expect("worker body result produced")
        .expect("worker-result-ready signal");
    let _ = release_result.send(());
    let completed = ready_snapshot(&reader).await;
    assert!(completed.worker_completed);
    assert!(completed.coordinator_future_polled);
    assert!(completed.worker_future_entered);
    assert!(completed.worker_join_observed);
    assert_eq!(
        completed.worker_result_disposition,
        WorkerResultDisposition::Recorded
    );
    assert!(!completed.worker_abort_requested);
    assert!(!completed.worker_result_unobserved);
    assert_eq!(completed.observations, vec![EffectObservation::Known(65)]);
    tokio::time::timeout(candidate::WATCHDOG, worker_dropped)
        .await
        .expect("normal worker future ended")
        .expect("worker future drop signal");

    drop(owner);
    drop(reader);
    assert!(
        tokio::time::timeout(candidate::WATCHDOG, supervisor_task.join())
            .await
            .expect("coordinator join watchdog")
            .is_ok()
    );
}

#[tokio::test]
async fn cancelled_join_waiter_leaves_handle_owned_and_normal_join_observed() {
    let (finish_worker_tx, finish_worker_rx) = oneshot::channel();
    let (owner, supervisor_task) = candidate::spawn_operation(8, 2, move |publisher| async move {
        publisher.observe(Publication::Visible).await.unwrap();
        publisher.observe(Publication::Acknowledged).await.unwrap();
        let _ = finish_worker_rx.await;
        EffectObservation::Known(41)
    });
    let reader = owner.reader();
    reader
        .wait_for(|state| state.publication == Publication::Acknowledged)
        .await
        .expect("publication acknowledgment observed");
    let (coordinator_entered, release_coordinator) = owner.pause_coordinator_for_test().await;
    coordinator_entered
        .await
        .expect("coordinator reached barrier");
    let task = Arc::new(AsyncMutex::new(supervisor_task));
    let (started_tx, started_rx) = oneshot::channel();
    let waiter_task = {
        let task = task.clone();
        tokio::spawn(async move { task.lock().await.join_started_for_test(started_tx).await })
    };
    tokio::time::timeout(candidate::WATCHDOG, started_rx)
        .await
        .expect("join waiter started")
        .expect("join waiter start signal");
    waiter_task.abort();
    assert!(matches!(
        waiter_task.await,
        Err(error) if error.is_cancelled()
    ));

    {
        let guard = task.lock().await;
        assert_eq!(require_join_observer(&guard), Ok(()));
    }
    let still_owned = reader.snapshot().await;
    assert_eq!(still_owned.owner, OwnerRole::Initiator);
    assert!(!still_owned.operation_cancelled);
    assert!(!still_owned.coordinator_abort_requested);
    assert!(!still_owned.coordinator_join_observed);
    let _ = release_coordinator.send(());
    let _ = finish_worker_tx.send(());
    let _ = reader
        .wait_for(|state| state.worker_completed)
        .await
        .expect("worker completion observed");
    drop(owner);
    drop(reader);
    let join_result = tokio::time::timeout(candidate::WATCHDOG, async {
        task.lock().await.join().await
    })
    .await
    .expect("retained join watchdog");
    assert!(join_result.is_ok());
    assert!(task.lock().await.join_observation_is_owned_for_test());
}

#[tokio::test]
async fn cancelled_abort_waiter_keeps_join_unresolved_then_observable() {
    let (owner, supervisor_task) =
        candidate::spawn_operation(8, 2, |_| async move { EffectObservation::Known(42) });
    let reader = owner.reader();
    let (coordinator_entered, _release_coordinator) = owner.pause_coordinator_for_test().await;
    coordinator_entered
        .await
        .expect("coordinator reached barrier");
    let task = Arc::new(AsyncMutex::new(supervisor_task));
    let (abort_requested_tx, abort_requested_rx) = oneshot::channel();
    let (resume_tx, resume_rx) = oneshot::channel();
    let abort_waiter = {
        let task = task.clone();
        tokio::spawn(async move {
            task.lock()
                .await
                .abort_and_join_paused_for_test(abort_requested_tx, resume_rx)
                .await
        })
    };
    tokio::time::timeout(candidate::WATCHDOG, abort_requested_rx)
        .await
        .expect("abort request observed")
        .expect("abort request signal");
    let pending = reader.snapshot().await;
    assert!(pending.coordinator_abort_requested);
    assert!(!pending.coordinator_join_observed);
    assert!(pending.supervisor_lost);
    assert_eq!(
        owner.admit_protected_operation().await,
        Err(Refusal::SupervisorLost)
    );
    abort_waiter.abort();
    assert!(matches!(
        abort_waiter.await,
        Err(error) if error.is_cancelled()
    ));
    drop(resume_tx);
    assert_eq!(
        require_join_observer(&*task.lock().await),
        Ok(()),
        "cancelling the abort-result waiter leaves the JoinHandle in its guard"
    );
    let still_unobserved = reader.snapshot().await;
    assert!(still_unobserved.coordinator_abort_requested);
    assert!(!still_unobserved.coordinator_join_observed);

    let observed = task.lock().await.join().await;
    assert!(matches!(
        observed,
        Err(SupervisorJoinError::Task(error)) if error.is_cancelled()
    ));
    assert!(reader.snapshot().await.coordinator_join_observed);
    drop(owner);
    drop(reader);
}

#[tokio::test]
async fn post_abort_watchdog_timeout_is_unresolved_until_retained_join_is_polled() {
    let (owner, supervisor_task) =
        candidate::spawn_operation(8, 2, |_| async move { EffectObservation::Known(43) });
    let reader = owner.reader();
    let (coordinator_entered, _release_coordinator) = owner.pause_coordinator_for_test().await;
    coordinator_entered
        .await
        .expect("coordinator reached barrier");
    let task = Arc::new(AsyncMutex::new(supervisor_task));
    let (watchdog_entered_tx, watchdog_entered_rx) = oneshot::channel();
    let (release_watchdog_tx, release_watchdog_rx) = oneshot::channel();
    let watchdog_waiter = {
        let task = task.clone();
        tokio::spawn(async move {
            task.lock()
                .await
                .abort_and_join_watchdog_for_test(
                    std::time::Duration::from_millis(10),
                    watchdog_entered_tx,
                    release_watchdog_rx,
                )
                .await
        })
    };
    tokio::time::timeout(candidate::WATCHDOG, watchdog_entered_rx)
        .await
        .expect("post-abort wait entered")
        .expect("post-abort wait signal");
    assert!(matches!(
        tokio::time::timeout(candidate::WATCHDOG, watchdog_waiter)
            .await
            .expect("watchdog result bounded")
            .expect("watchdog task joined"),
        Err(SupervisorJoinError::WatchdogUnresolved)
    ));
    drop(release_watchdog_tx);
    let pending = reader.snapshot().await;
    assert!(pending.coordinator_abort_requested);
    assert!(!pending.coordinator_join_observed);
    assert_eq!(
        require_join_observer(&*task.lock().await),
        Ok(()),
        "watchdog timeout preserves the join handle for later observation"
    );
    assert!(matches!(
        task.lock().await.join().await,
        Err(SupervisorJoinError::Task(error)) if error.is_cancelled()
    ));
    assert!(reader.snapshot().await.coordinator_join_observed);
    drop(owner);
    drop(reader);
}

#[tokio::test]
async fn detached_join_sensitivity_detects_unowned_observation() {
    let (owner, supervisor_task) =
        candidate::spawn_operation(8, 2, |_| async move { EffectObservation::Known(44) });
    let reader = owner.reader();
    let (coordinator_entered, _release_coordinator) = owner.pause_coordinator_for_test().await;
    coordinator_entered
        .await
        .expect("coordinator reached barrier");
    let task = Arc::new(AsyncMutex::new(supervisor_task));
    let (started_tx, started_rx) = oneshot::channel();
    let detached_waiter = {
        let task = task.clone();
        tokio::spawn(async move {
            let _ = started_tx.send(());
            task.lock().await.join_detached_for_test().await
        })
    };
    tokio::time::timeout(candidate::WATCHDOG, started_rx)
        .await
        .expect("detached join waiter started")
        .expect("detached waiter signal");
    detached_waiter.abort();
    assert!(matches!(
        detached_waiter.await,
        Err(error) if error.is_cancelled()
    ));
    assert_eq!(
        require_join_observer(&*task.lock().await),
        Err("coordinator JoinHandle has no retained observer")
    );

    drop(owner);
    let detached_guard = Arc::try_unwrap(task)
        .ok()
        .expect("detached waiter released the task guard")
        .into_inner();
    drop(detached_guard);
    let unresolved = reader.snapshot().await;
    assert!(unresolved.supervisor_lost);
    assert!(unresolved.coordinator_abort_requested);
    assert!(!unresolved.coordinator_join_observed);
    drop(reader);
}

#[tokio::test]
async fn coordinator_panic_is_joined_and_marks_supervisor_lost() {
    let (owner, mut supervisor_task) = candidate::spawn_operation(8, 2, |publisher| async move {
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
    let (owner, mut supervisor_task) =
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
    let (owner, mut supervisor_task) = candidate::spawn_operation(8, 3, |publisher| async move {
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
    let (cancelled_owner, mut cancelled_task) =
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

    let (retired_owner, mut retired_task) =
        candidate::spawn_operation(8, 2, |publisher| async move {
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
