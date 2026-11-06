//! Non-wired, in-process A33-F1 / E27 ownership prototype.
//!
//! This test-support component exposes only synthetic protected-operation
//! admission. It has no production consensus, signer, storage, network,
//! startup, or restore capabilities.

use std::future::Future;
use std::sync::{
    atomic::{AtomicBool, AtomicU8, Ordering},
    Arc,
};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, watch, Mutex};
use tokio::task::{JoinError, JoinHandle};
use tokio::time::timeout;

pub(crate) const WATCHDOG: Duration = Duration::from_secs(3);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OwnerRole {
    Initiator,
    Supervisor,
    Lost,
}

impl OwnerRole {
    fn code(self) -> u8 {
        match self {
            Self::Initiator => 0,
            Self::Supervisor => 1,
            Self::Lost => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Publication {
    None,
    Pending,
    Visible,
    Acknowledged,
    Failed,
    Uncertain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EffectObservation {
    Known(u64),
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WorkerStatus {
    Running,
    Completed,
    Cancelled,
    Panicked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum WorkerResultDisposition {
    Pending = 0,
    NotObserved = 1,
    ObservedUnrecorded = 2,
    Recorded = 3,
}

impl WorkerResultDisposition {
    fn from_code(code: u8) -> Self {
        match code {
            1 => Self::NotObserved,
            2 => Self::ObservedUnrecorded,
            3 => Self::Recorded,
            _ => Self::Pending,
        }
    }
}

// Recorded means the join result was applied to owner status/overflow state;
// it does not guarantee that the exact observation fit in the bounded list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub(crate) owner: OwnerRole,
    pub(crate) operation_cancelled: bool,
    pub(crate) operation_retired: bool,
    pub(crate) refusal_closed: bool,
    pub(crate) participation_allowed: bool,
    pub(crate) publication: Publication,
    pub(crate) worker_status: WorkerStatus,
    pub(crate) worker_completed: bool,
    pub(crate) observations: Vec<EffectObservation>,
    pub(crate) outcome_unknown: bool,
    pub(crate) outcome_conflict: bool,
    pub(crate) outcome_overflow: bool,
    pub(crate) control_overflow: bool,
    pub(crate) supervisor_lost: bool,
    pub(crate) coordinator_abort_requested: bool,
    pub(crate) coordinator_join_observed: bool,
    pub(crate) coordinator_future_dropped: bool,
    pub(crate) coordinator_future_polled: bool,
    pub(crate) worker_abort_requested: bool,
    pub(crate) worker_future_entered: bool,
    pub(crate) worker_join_observed: bool,
    pub(crate) worker_result_unobserved: bool,
    pub(crate) worker_result_disposition: WorkerResultDisposition,
    pub(crate) protected_admissions: usize,
}

impl Snapshot {
    fn initial() -> Self {
        Self {
            owner: OwnerRole::Initiator,
            operation_cancelled: false,
            operation_retired: false,
            refusal_closed: true,
            participation_allowed: false,
            publication: Publication::Pending,
            worker_status: WorkerStatus::Running,
            worker_completed: false,
            observations: Vec::new(),
            outcome_unknown: false,
            outcome_conflict: false,
            outcome_overflow: false,
            control_overflow: false,
            supervisor_lost: false,
            coordinator_abort_requested: false,
            coordinator_join_observed: false,
            coordinator_future_dropped: false,
            coordinator_future_polled: false,
            worker_abort_requested: false,
            worker_future_entered: false,
            worker_join_observed: false,
            worker_result_unobserved: false,
            worker_result_disposition: WorkerResultDisposition::Pending,
            protected_admissions: 0,
        }
    }

    fn effect_is_known_and_consistent(&self) -> bool {
        !self.observations.is_empty()
            && !self.outcome_unknown
            && !self.outcome_conflict
            && !self.outcome_overflow
            && self
                .observations
                .iter()
                .all(|observation| matches!(observation, EffectObservation::Known(_)))
    }

    pub(crate) fn refuse(&self, role: OwnerRole) -> Result<(), Refusal> {
        if self.supervisor_lost {
            return Err(Refusal::SupervisorLost);
        }
        if self.control_overflow || self.outcome_overflow {
            return Err(Refusal::CapacityUncertain);
        }
        if self.operation_cancelled {
            return Err(Refusal::OperationCancelled);
        }
        if self.operation_retired {
            return Err(Refusal::OperationRetired);
        }
        if self.owner != role || matches!(role, OwnerRole::Lost) {
            return Err(Refusal::NotCurrentOwner);
        }
        if !self.refusal_closed || self.participation_allowed {
            return Err(Refusal::RefusalInvariant);
        }
        if self.publication != Publication::Acknowledged {
            return Err(Refusal::PublicationNotAcknowledged);
        }
        if !self.worker_completed {
            return Err(Refusal::WorkerStillRunning);
        }
        if !self.effect_is_known_and_consistent() {
            return Err(Refusal::EffectUnresolved);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    CapacityUncertain,
    EffectUnresolved,
    OperationCancelled,
    OperationRetired,
    NotCurrentOwner,
    PublicationNotAcknowledged,
    RefusalInvariant,
    SupervisorLost,
    WorkerStillRunning,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RecordError {
    Capacity(EffectObservation),
    ChannelClosed(EffectObservation),
    Refused(Refusal, EffectObservation),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PublishError {
    Capacity(Publication),
    ChannelClosed(Publication),
    InvalidTransition(Publication),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HandoffError {
    ReceiverUnavailable,
    Refused(Refusal),
    AcceptanceLost,
}

#[derive(Debug)]
pub(crate) enum SupervisorJoinError {
    Task(JoinError),
    WatchdogAborted(JoinError),
    CompletedAfterWatchdog,
    WatchdogUnresolved,
}

#[derive(Clone)]
struct Shared {
    state: Arc<Mutex<Snapshot>>,
    state_updates: watch::Sender<Snapshot>,
    overflow: Arc<AtomicBool>,
    supervisor_lost: Arc<AtomicBool>,
    coordinator_abort_requested: Arc<AtomicBool>,
    coordinator_join_observed: Arc<AtomicBool>,
    coordinator_future_dropped: Arc<AtomicBool>,
    coordinator_future_polled: Arc<AtomicBool>,
    worker_abort_requested: Arc<AtomicBool>,
    worker_future_entered: Arc<AtomicBool>,
    worker_join_observed: Arc<AtomicBool>,
    worker_result_unobserved: Arc<AtomicBool>,
    worker_result_disposition: Arc<AtomicU8>,
    current_owner: Arc<AtomicU8>,
}

#[derive(Clone)]
struct ReadShared {
    state: Arc<Mutex<Snapshot>>,
    state_updates: watch::Sender<Snapshot>,
    overflow: Arc<AtomicBool>,
    supervisor_lost: Arc<AtomicBool>,
    coordinator_abort_requested: Arc<AtomicBool>,
    coordinator_join_observed: Arc<AtomicBool>,
    coordinator_future_dropped: Arc<AtomicBool>,
    coordinator_future_polled: Arc<AtomicBool>,
    worker_abort_requested: Arc<AtomicBool>,
    worker_future_entered: Arc<AtomicBool>,
    worker_join_observed: Arc<AtomicBool>,
    worker_result_unobserved: Arc<AtomicBool>,
    worker_result_disposition: Arc<AtomicU8>,
    current_owner: Arc<AtomicU8>,
}

impl Shared {
    fn read_shared(&self) -> ReadShared {
        ReadShared {
            state: self.state.clone(),
            state_updates: self.state_updates.clone(),
            overflow: self.overflow.clone(),
            supervisor_lost: self.supervisor_lost.clone(),
            coordinator_abort_requested: self.coordinator_abort_requested.clone(),
            coordinator_join_observed: self.coordinator_join_observed.clone(),
            coordinator_future_dropped: self.coordinator_future_dropped.clone(),
            coordinator_future_polled: self.coordinator_future_polled.clone(),
            worker_abort_requested: self.worker_abort_requested.clone(),
            worker_future_entered: self.worker_future_entered.clone(),
            worker_join_observed: self.worker_join_observed.clone(),
            worker_result_unobserved: self.worker_result_unobserved.clone(),
            worker_result_disposition: self.worker_result_disposition.clone(),
            current_owner: self.current_owner.clone(),
        }
    }
}

pub(crate) struct OperationOwner {
    commands: mpsc::Sender<Command>,
    shared: Shared,
    role: OwnerRole,
    report_owner_loss: bool,
}

impl OperationOwner {
    pub(crate) fn role(&self) -> OwnerRole {
        self.role
    }

    pub(crate) fn reader(&self) -> StateReader {
        StateReader {
            updates: self.shared.state_updates.subscribe(),
            shared: self.shared.read_shared(),
            #[cfg(test)]
            commands: self.commands.clone(),
        }
    }

    pub(crate) async fn admit_protected_operation(&self) -> Result<(), Refusal> {
        let (reply, result) = oneshot::channel();
        let command = Command::Admit {
            role: self.role,
            reply,
        };
        match self.commands.try_send(command) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.shared.overflow.store(true, Ordering::SeqCst);
                return Err(Refusal::CapacityUncertain);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(Refusal::SupervisorLost);
            }
        }
        result.await.unwrap_or(Err(Refusal::SupervisorLost))
    }

    pub(crate) async fn cancel_operation(&self) -> Result<(), Refusal> {
        self.request(|reply| Command::Cancel {
            role: self.role,
            reply,
        })
        .await
    }

    #[cfg(test)]
    pub(crate) async fn hold_state_for_test(&self) -> tokio::sync::MutexGuard<'_, Snapshot> {
        self.shared.state.lock().await
    }

    #[cfg(test)]
    // Seeds a full internal collection to exercise the defensive join-overflow branch.
    // Normal RecordOutcome admission reserves a slot while the worker is running.
    pub(crate) async fn fill_observations_for_capacity_boundary_test(
        &self,
        observations: Vec<EffectObservation>,
        outcome_capacity: usize,
    ) {
        assert_eq!(observations.len(), outcome_capacity);
        let mut state = self.shared.state.lock().await;
        assert_eq!(state.worker_status, WorkerStatus::Running);
        assert!(state.observations.is_empty());
        for observation in observations {
            add_observation(&mut state, observation);
        }
        publish(&self.shared, &state);
    }

    pub(crate) async fn retire(&self) -> Result<(), Refusal> {
        self.request(|reply| Command::Retire {
            role: self.role,
            reply,
        })
        .await
    }

    #[cfg(test)]
    pub(crate) async fn panic_supervisor_for_test(&self) {
        self.commands
            .send(Command::PanicForTest)
            .await
            .expect("supervisor remains available for panic sensitivity test");
    }

    #[cfg(test)]
    pub(crate) async fn pause_coordinator_for_test(
        &self,
    ) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        self.commands
            .send(Command::PauseCoordinator {
                entered: entered_tx,
                release: release_rx,
            })
            .await
            .expect("coordinator command loop is running");
        (entered_rx, release_tx)
    }

    #[cfg(test)]
    pub(crate) async fn admit_as_for_test(&self, role: OwnerRole) -> Result<(), Refusal> {
        let (reply, result) = oneshot::channel();
        self.commands
            .send(Command::Admit { role, reply })
            .await
            .map_err(|_| Refusal::SupervisorLost)?;
        result.await.unwrap_or(Err(Refusal::SupervisorLost))
    }

    #[cfg(test)]
    pub(crate) async fn mark_owner_lost_for_test(&self, role: OwnerRole) {
        self.shared
            .current_owner
            .store(OwnerRole::Lost.code(), Ordering::SeqCst);
        self.shared.state_updates.send_modify(|state| {
            state.owner = OwnerRole::Lost;
            state.refusal_closed = true;
            state.participation_allowed = false;
        });
        self.commands
            .send(Command::OwnerDropped { role })
            .await
            .expect("coordinator remains available for sensitivity cleanup");
    }

    pub(crate) async fn record_outcome(
        &self,
        observation: EffectObservation,
    ) -> Result<(), RecordError> {
        let (reply, result) = oneshot::channel();
        match self.commands.try_send(Command::RecordOutcome {
            role: self.role,
            observation,
            reply,
        }) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.shared.overflow.store(true, Ordering::SeqCst);
                return Err(RecordError::Capacity(observation));
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(RecordError::ChannelClosed(observation));
            }
        }
        result
            .await
            .unwrap_or(Err(RecordError::ChannelClosed(observation)))
    }

    pub(crate) async fn observe_publication(
        &self,
        publication: Publication,
    ) -> Result<(), PublishError> {
        let (reply, result) = oneshot::channel();
        match self.commands.try_send(Command::ObservePublication {
            role: self.role,
            publication,
            reply,
        }) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.shared.overflow.store(true, Ordering::SeqCst);
                return Err(PublishError::Capacity(publication));
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(PublishError::ChannelClosed(publication));
            }
        }
        result
            .await
            .unwrap_or(Err(PublishError::ChannelClosed(publication)))
    }

    pub(crate) async fn offer_handoff(
        self,
        receiver: &mpsc::Sender<HandoffOffer>,
    ) -> Result<(), HandoffError> {
        let (ack, accepted) = oneshot::channel();
        let offer = HandoffOffer {
            commands: self.commands.clone(),
            shared: self.shared.clone(),
            ack: Some(ack),
        };
        receiver
            .send(offer)
            .await
            .map_err(|_| HandoffError::ReceiverUnavailable)?;
        match accepted.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(refusal)) => Err(HandoffError::Refused(refusal)),
            Err(_) => Err(HandoffError::AcceptanceLost),
        }
    }

    async fn request(
        &self,
        command: impl FnOnce(oneshot::Sender<Result<(), Refusal>>) -> Command,
    ) -> Result<(), Refusal> {
        let (reply, result) = oneshot::channel();
        self.commands
            .send(command(reply))
            .await
            .map_err(|_| Refusal::SupervisorLost)?;
        result.await.unwrap_or(Err(Refusal::SupervisorLost))
    }
}

impl Drop for OperationOwner {
    fn drop(&mut self) {
        if self.role == OwnerRole::Lost {
            return;
        }
        let current_owner = &self.shared.current_owner;
        let lost = if !self.report_owner_loss
            || self.shared.state_updates.borrow().operation_retired
        {
            false
        } else if self.role == OwnerRole::Initiator {
            current_owner
                .compare_exchange(
                    OwnerRole::Initiator.code(),
                    OwnerRole::Lost.code(),
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                )
                .is_ok()
        } else {
            current_owner.swap(OwnerRole::Lost.code(), Ordering::SeqCst) != OwnerRole::Lost.code()
        };
        if lost {
            self.shared.state_updates.send_modify(|state| {
                state.owner = OwnerRole::Lost;
                state.refusal_closed = true;
                state.participation_allowed = false;
            });
        }
        if lost
            && self
                .commands
                .try_send(Command::OwnerDropped { role: self.role })
                .is_err()
        {
            self.shared.overflow.store(true, Ordering::SeqCst);
        }
    }
}

pub(crate) struct HandoffOffer {
    commands: mpsc::Sender<Command>,
    shared: Shared,
    ack: Option<oneshot::Sender<Result<(), Refusal>>>,
}

impl HandoffOffer {
    pub(crate) async fn accept(mut self) -> Result<OperationOwner, Refusal> {
        self.accept_inner(None, None).await
    }

    #[cfg(test)]
    pub(crate) async fn accept_paused_for_test(
        mut self,
        request_sent: oneshot::Sender<()>,
        reply_sent: oneshot::Sender<()>,
        continue_accept: oneshot::Receiver<()>,
    ) -> Result<OperationOwner, Refusal> {
        self.accept_inner(Some(request_sent), Some((reply_sent, continue_accept)))
            .await
    }

    #[cfg(test)]
    pub(crate) async fn accept_without_loss_guard_for_test(
        mut self,
        request_sent: oneshot::Sender<()>,
        reply_sent: oneshot::Sender<()>,
        continue_accept: oneshot::Receiver<()>,
    ) -> Result<OperationOwner, Refusal> {
        self.accept_inner_with_loss(
            Some(request_sent),
            Some((reply_sent, continue_accept)),
            false,
        )
        .await
    }

    async fn accept_inner(
        &mut self,
        request_sent: Option<oneshot::Sender<()>>,
        pause: Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>,
    ) -> Result<OperationOwner, Refusal> {
        self.accept_inner_with_loss(request_sent, pause, true).await
    }

    async fn accept_inner_with_loss(
        &mut self,
        request_sent: Option<oneshot::Sender<()>>,
        pause: Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>,
        report_owner_loss: bool,
    ) -> Result<OperationOwner, Refusal> {
        let (reply_sent, continue_accept) = match pause {
            Some((reply_sent, continue_accept)) => (Some(reply_sent), Some(continue_accept)),
            None => (None, None),
        };
        let owner = OperationOwner {
            commands: self.commands.clone(),
            shared: self.shared.clone(),
            role: OwnerRole::Supervisor,
            report_owner_loss,
        };
        let (reply, result) = oneshot::channel();
        self.commands
            .send(Command::AcceptHandoff {
                reply,
                initiator_ack: self.ack.take(),
                reply_sent,
            })
            .await
            .map_err(|_| Refusal::SupervisorLost)?;
        if let Some(sent) = request_sent {
            let _ = sent.send(());
        }
        if let Some(continue_accept) = continue_accept {
            let _ = continue_accept.await;
        }
        result.await.unwrap_or(Err(Refusal::SupervisorLost))?;
        Ok(owner)
    }
}

pub(crate) struct StateReader {
    updates: watch::Receiver<Snapshot>,
    shared: ReadShared,
    #[cfg(test)]
    commands: mpsc::Sender<Command>,
}

impl StateReader {
    pub(crate) async fn snapshot(&self) -> Snapshot {
        let mut state = self.shared.state.lock().await.clone();
        state.control_overflow |= self.shared.overflow.load(Ordering::SeqCst);
        state.supervisor_lost |= self.shared.supervisor_lost.load(Ordering::SeqCst);
        state.coordinator_abort_requested |= self
            .shared
            .coordinator_abort_requested
            .load(Ordering::SeqCst);
        state.coordinator_join_observed |=
            self.shared.coordinator_join_observed.load(Ordering::SeqCst);
        state.coordinator_future_dropped |= self
            .shared
            .coordinator_future_dropped
            .load(Ordering::SeqCst);
        state.coordinator_future_polled |=
            self.shared.coordinator_future_polled.load(Ordering::SeqCst);
        state.worker_abort_requested |= self.shared.worker_abort_requested.load(Ordering::SeqCst);
        state.worker_future_entered |= self.shared.worker_future_entered.load(Ordering::SeqCst);
        state.worker_join_observed |= self.shared.worker_join_observed.load(Ordering::SeqCst);
        state.worker_result_unobserved |=
            self.shared.worker_result_unobserved.load(Ordering::SeqCst);
        state.worker_result_disposition = WorkerResultDisposition::from_code(
            self.shared.worker_result_disposition.load(Ordering::SeqCst),
        );
        if self.shared.current_owner.load(Ordering::SeqCst) == OwnerRole::Lost.code() {
            state.owner = OwnerRole::Lost;
            state.refusal_closed = true;
            state.participation_allowed = false;
        }
        if state.supervisor_lost {
            state.refusal_closed = true;
            state.participation_allowed = false;
        }
        state
    }

    pub(crate) async fn wait_for(
        &self,
        predicate: impl Fn(&Snapshot) -> bool,
    ) -> Result<Snapshot, &'static str> {
        let mut updates = self.updates.clone();
        timeout(WATCHDOG, async {
            loop {
                let snapshot = self.snapshot().await;
                if predicate(&snapshot) {
                    return Ok(snapshot);
                }
                updates
                    .changed()
                    .await
                    .map_err(|_| "state supervisor stopped before condition")?;
            }
        })
        .await
        .map_err(|_| "state watchdog expired")?
    }

    #[cfg(test)]
    pub(crate) async fn admit_as(&self, role: OwnerRole) -> Result<(), Refusal> {
        let (reply, result) = oneshot::channel();
        self.commands
            .send(Command::Admit { role, reply })
            .await
            .map_err(|_| Refusal::SupervisorLost)?;
        result.await.unwrap_or(Err(Refusal::SupervisorLost))
    }

    #[cfg(test)]
    pub(crate) async fn mark_owner_lost_for_test(&self, role: OwnerRole) {
        self.shared
            .current_owner
            .store(OwnerRole::Lost.code(), Ordering::SeqCst);
        self.shared.state_updates.send_modify(|state| {
            state.owner = OwnerRole::Lost;
            state.refusal_closed = true;
            state.participation_allowed = false;
        });
        self.commands
            .send(Command::OwnerDropped { role })
            .await
            .expect("coordinator remains available for sensitivity cleanup");
    }

    #[cfg(test)]
    pub(crate) fn clear_worker_result_unobserved_for_test(&self) {
        self.shared
            .worker_result_unobserved
            .store(false, Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn classify_worker_result_for_sensitivity_test(
        &self,
        disposition: WorkerResultDisposition,
    ) {
        self.shared
            .worker_result_disposition
            .store(disposition as u8, Ordering::SeqCst);
        self.shared.state_updates.send_modify(|_| {});
    }

    #[cfg(test)]
    pub(crate) fn fill_command_queue_for_test(&self) -> Result<(), ()> {
        let (reply, result) = oneshot::channel();
        drop(result);
        self.commands
            .try_send(Command::Admit {
                role: OwnerRole::Supervisor,
                reply,
            })
            .map_err(|_| ())
    }
}

pub(crate) struct MockPublisher {
    commands: mpsc::Sender<Command>,
    shared: Shared,
}

impl MockPublisher {
    pub(crate) async fn observe(&self, publication: Publication) -> Result<(), PublishError> {
        let (reply, result) = oneshot::channel();
        match self.commands.try_send(Command::ObservePublication {
            role: OwnerRole::Initiator,
            publication,
            reply,
        }) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.shared.overflow.store(true, Ordering::SeqCst);
                return Err(PublishError::Capacity(publication));
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(PublishError::ChannelClosed(publication));
            }
        }
        result
            .await
            .unwrap_or(Err(PublishError::ChannelClosed(publication)))
    }
}

pub(crate) struct SupervisorTask {
    join: Option<JoinHandle<()>>,
    abort: tokio::task::AbortHandle,
    worker_abort_for_test: tokio::task::AbortHandle,
    shared: ReadShared,
}

impl SupervisorTask {
    pub(crate) async fn join(&mut self) -> Result<(), SupervisorJoinError> {
        let join = self.join.as_mut().expect("supervisor join handle retained");
        match timeout(WATCHDOG, join).await {
            Ok(result) => {
                self.shared
                    .coordinator_join_observed
                    .store(true, Ordering::SeqCst);
                if result.is_err() {
                    self.shared.supervisor_lost.store(true, Ordering::SeqCst);
                }
                result.map_err(SupervisorJoinError::Task)
            }
            Err(_) => {
                self.request_abort();
                let join = self.join.as_mut().expect("supervisor join handle retained");
                self.shared.supervisor_lost.store(true, Ordering::SeqCst);
                match timeout(WATCHDOG, join).await {
                    Ok(result) => {
                        self.shared
                            .coordinator_join_observed
                            .store(true, Ordering::SeqCst);
                        match result {
                            Err(error) => Err(SupervisorJoinError::WatchdogAborted(error)),
                            Ok(()) => Err(SupervisorJoinError::CompletedAfterWatchdog),
                        }
                    }
                    Err(_) => Err(SupervisorJoinError::WatchdogUnresolved),
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) async fn join_started_for_test(
        &mut self,
        started: oneshot::Sender<()>,
    ) -> Result<(), SupervisorJoinError> {
        let _ = started.send(());
        self.join().await
    }

    pub(crate) async fn abort_and_join(&mut self) -> Result<(), SupervisorJoinError> {
        self.request_abort();
        match self.wait_after_abort(WATCHDOG).await {
            Ok(result) => self.observe_join_result(result),
            Err(error) => Err(error),
        }
    }

    #[cfg(test)]
    pub(crate) async fn abort_and_join_paused_for_test(
        &mut self,
        entered: oneshot::Sender<()>,
        release: oneshot::Receiver<()>,
    ) -> Result<(), SupervisorJoinError> {
        self.request_abort();
        let _ = entered.send(());
        let join = self.join.as_mut().expect("supervisor join handle retained");
        match timeout(WATCHDOG, async {
            let _ = release.await;
            join.await
        })
        .await
        {
            Ok(result) => self.observe_join_result(result),
            Err(_) => Err(SupervisorJoinError::WatchdogUnresolved),
        }
    }

    #[cfg(test)]
    pub(crate) async fn abort_and_join_watchdog_for_test(
        &mut self,
        watchdog: Duration,
        entered: oneshot::Sender<()>,
        release: oneshot::Receiver<()>,
    ) -> Result<(), SupervisorJoinError> {
        self.request_abort();
        let _ = entered.send(());
        let join = self.join.as_mut().expect("supervisor join handle retained");
        match timeout(watchdog, async {
            let _ = release.await;
            join.await
        })
        .await
        {
            Ok(result) => self.observe_join_result(result),
            Err(_) => Err(SupervisorJoinError::WatchdogUnresolved),
        }
    }

    #[cfg(test)]
    pub(crate) async fn join_detached_for_test(&mut self) -> Result<(), SupervisorJoinError> {
        let mut detached = self.join.take().expect("supervisor join handle present");
        timeout(WATCHDOG, &mut detached)
            .await
            .map_err(|_| SupervisorJoinError::WatchdogUnresolved)?
            .map_err(SupervisorJoinError::Task)
    }

    #[cfg(test)]
    pub(crate) fn join_observation_is_owned_for_test(&self) -> bool {
        self.join.is_some() || self.shared.coordinator_join_observed.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) fn abort_worker_without_observer_for_test(&self) {
        self.worker_abort_for_test.abort();
    }

    async fn wait_after_abort(
        &mut self,
        watchdog: Duration,
    ) -> Result<Result<(), JoinError>, SupervisorJoinError> {
        let join = self.join.as_mut().expect("supervisor join handle retained");
        timeout(watchdog, join)
            .await
            .map_err(|_| SupervisorJoinError::WatchdogUnresolved)
    }

    fn request_abort(&self) {
        self.shared
            .coordinator_abort_requested
            .store(true, Ordering::SeqCst);
        self.shared.supervisor_lost.store(true, Ordering::SeqCst);
        self.abort.abort();
    }

    fn observe_join_result(
        &self,
        result: Result<(), JoinError>,
    ) -> Result<(), SupervisorJoinError> {
        self.shared
            .coordinator_join_observed
            .store(true, Ordering::SeqCst);
        if result.is_err() {
            self.shared.supervisor_lost.store(true, Ordering::SeqCst);
        }
        result.map_err(SupervisorJoinError::Task)
    }
}

impl Drop for SupervisorTask {
    fn drop(&mut self) {
        if !self.shared.coordinator_join_observed.load(Ordering::SeqCst) {
            self.shared
                .coordinator_abort_requested
                .store(true, Ordering::SeqCst);
            self.shared.supervisor_lost.store(true, Ordering::SeqCst);
            self.abort.abort();
        }
    }
}

pub(crate) fn spawn_operation<F, Fut>(
    command_capacity: usize,
    outcome_capacity: usize,
    work: F,
) -> (OperationOwner, SupervisorTask)
where
    F: FnOnce(MockPublisher) -> Fut + Send + 'static,
    Fut: Future<Output = EffectObservation> + Send + 'static,
{
    let (owner, supervisor, _) =
        spawn_operation_inner(command_capacity, outcome_capacity, work, None, None, true);
    (owner, supervisor)
}

#[cfg(test)]
pub(crate) fn spawn_operation_with_result_gate_for_test<F, Fut>(
    command_capacity: usize,
    outcome_capacity: usize,
    work: F,
) -> (
    OperationOwner,
    SupervisorTask,
    oneshot::Receiver<()>,
    oneshot::Sender<()>,
    oneshot::Receiver<()>,
)
where
    F: FnOnce(MockPublisher) -> Fut + Send + 'static,
    Fut: Future<Output = EffectObservation> + Send + 'static,
{
    let (result_ready_tx, result_ready_rx) = oneshot::channel();
    let (release_result_tx, release_result_rx) = oneshot::channel();
    let (worker_dropped_tx, worker_dropped_rx) = oneshot::channel();
    let (owner, supervisor, _) = spawn_operation_inner(
        command_capacity,
        outcome_capacity,
        work,
        Some(WorkerResultGate {
            result_ready: result_ready_tx,
            release_result: release_result_rx,
            worker_dropped: worker_dropped_tx,
        }),
        None,
        true,
    );
    (
        owner,
        supervisor,
        result_ready_rx,
        release_result_tx,
        worker_dropped_rx,
    )
}

#[cfg(test)]
pub(crate) fn spawn_operation_without_early_worker_guard_for_test<F, Fut>(
    command_capacity: usize,
    outcome_capacity: usize,
    work: F,
) -> (
    OperationOwner,
    SupervisorTask,
    oneshot::Receiver<()>,
    oneshot::Sender<()>,
    oneshot::Receiver<()>,
)
where
    F: FnOnce(MockPublisher) -> Fut + Send + 'static,
    Fut: Future<Output = EffectObservation> + Send + 'static,
{
    let (result_ready_tx, result_ready_rx) = oneshot::channel();
    let (release_result_tx, release_result_rx) = oneshot::channel();
    let (worker_dropped_tx, worker_dropped_rx) = oneshot::channel();
    let (owner, supervisor, _) = spawn_operation_inner(
        command_capacity,
        outcome_capacity,
        work,
        Some(WorkerResultGate {
            result_ready: result_ready_tx,
            release_result: release_result_rx,
            worker_dropped: worker_dropped_tx,
        }),
        None,
        false,
    );
    (
        owner,
        supervisor,
        result_ready_rx,
        release_result_tx,
        worker_dropped_rx,
    )
}

#[cfg(test)]
pub(crate) fn spawn_operation_with_join_apply_gate_for_test<F, Fut>(
    command_capacity: usize,
    outcome_capacity: usize,
    work: F,
) -> (
    OperationOwner,
    SupervisorTask,
    oneshot::Receiver<()>,
    oneshot::Sender<()>,
)
where
    F: FnOnce(MockPublisher) -> Fut + Send + 'static,
    Fut: Future<Output = EffectObservation> + Send + 'static,
{
    let (observed_tx, observed_rx) = oneshot::channel();
    let (release_apply_tx, release_apply_rx) = oneshot::channel();
    let (owner, supervisor, _) = spawn_operation_inner(
        command_capacity,
        outcome_capacity,
        work,
        None,
        Some(JoinApplyGate {
            result_observed: observed_tx,
            release_application: release_apply_rx,
        }),
        true,
    );
    (owner, supervisor, observed_rx, release_apply_tx)
}

fn spawn_operation_inner<F, Fut>(
    command_capacity: usize,
    outcome_capacity: usize,
    work: F,
    result_gate: Option<WorkerResultGate>,
    join_apply_gate: Option<JoinApplyGate>,
    guard_worker_before_coordinator_spawn: bool,
) -> (OperationOwner, SupervisorTask, tokio::task::AbortHandle)
where
    F: FnOnce(MockPublisher) -> Fut + Send + 'static,
    Fut: Future<Output = EffectObservation> + Send + 'static,
{
    assert!(command_capacity > 0, "command capacity must be positive");
    assert!(
        outcome_capacity > 0,
        "reserve one observation for worker result"
    );

    let (commands, receiver) = mpsc::channel(command_capacity);
    let state = Arc::new(Mutex::new(Snapshot::initial()));
    let (state_updates, _) = watch::channel(Snapshot::initial());
    let overflow = Arc::new(AtomicBool::new(false));
    let supervisor_lost = Arc::new(AtomicBool::new(false));
    let coordinator_abort_requested = Arc::new(AtomicBool::new(false));
    let coordinator_join_observed = Arc::new(AtomicBool::new(false));
    let coordinator_future_dropped = Arc::new(AtomicBool::new(false));
    let coordinator_future_polled = Arc::new(AtomicBool::new(false));
    let worker_abort_requested = Arc::new(AtomicBool::new(false));
    let worker_future_entered = Arc::new(AtomicBool::new(false));
    let worker_join_observed = Arc::new(AtomicBool::new(false));
    let worker_result_unobserved = Arc::new(AtomicBool::new(false));
    let worker_result_disposition = Arc::new(AtomicU8::new(WorkerResultDisposition::Pending as u8));
    let current_owner = Arc::new(AtomicU8::new(OwnerRole::Initiator.code()));
    let shared = Shared {
        state,
        state_updates,
        overflow,
        supervisor_lost,
        coordinator_abort_requested,
        coordinator_join_observed,
        coordinator_future_dropped,
        coordinator_future_polled,
        worker_abort_requested,
        worker_future_entered,
        worker_join_observed,
        worker_result_unobserved,
        worker_result_disposition,
        current_owner,
    };

    let publisher = MockPublisher {
        commands: commands.clone(),
        shared: shared.clone(),
    };
    let (result_gate, worker_drop_notify) = match result_gate {
        Some(gate) => (
            Some((gate.result_ready, gate.release_result)),
            Some(WorkerDropNotify(Some(gate.worker_dropped))),
        ),
        None => (None, None),
    };
    let worker_shared = shared.clone();
    let worker = tokio::spawn(async move {
        let _drop_notify = worker_drop_notify;
        worker_shared
            .worker_future_entered
            .store(true, Ordering::SeqCst);
        let result_gate = result_gate;
        let result = work(publisher).await;
        if let Some((result_ready, release_result)) = result_gate {
            let _ = result_ready.send(());
            let _ = release_result.await;
        }
        result
    });
    let worker_abort_for_test = worker.abort_handle();
    let worker = if guard_worker_before_coordinator_spawn {
        WorkerForCoordinator::Guarded(WorkerJoin::new(worker, shared.clone()))
    } else {
        WorkerForCoordinator::Raw(worker)
    };
    let supervisor_shared = shared.clone();
    let coordinator_drop_notify = CoordinatorDropNotify(supervisor_shared.clone());
    let join = tokio::spawn(async move {
        let _drop_notify = coordinator_drop_notify;
        supervisor_shared
            .coordinator_future_polled
            .store(true, Ordering::SeqCst);
        let worker = match worker {
            WorkerForCoordinator::Guarded(worker) => worker,
            WorkerForCoordinator::Raw(worker) => WorkerJoin::new(worker, supervisor_shared.clone()),
        };
        run_supervisor(
            receiver,
            worker,
            supervisor_shared,
            outcome_capacity,
            join_apply_gate,
        )
        .await;
    });
    let abort = join.abort_handle();

    (
        OperationOwner {
            commands,
            shared: shared.clone(),
            role: OwnerRole::Initiator,
            report_owner_loss: true,
        },
        SupervisorTask {
            join: Some(join),
            abort,
            worker_abort_for_test: worker_abort_for_test.clone(),
            shared: shared.read_shared(),
        },
        worker_abort_for_test,
    )
}

#[cfg(test)]
struct WorkerResultGate {
    result_ready: oneshot::Sender<()>,
    release_result: oneshot::Receiver<()>,
    worker_dropped: oneshot::Sender<()>,
}

#[cfg(test)]
struct JoinApplyGate {
    result_observed: oneshot::Sender<()>,
    release_application: oneshot::Receiver<()>,
}

#[cfg(test)]
struct WorkerDropNotify(Option<oneshot::Sender<()>>);

#[cfg(test)]
impl Drop for WorkerDropNotify {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

enum WorkerForCoordinator {
    Guarded(WorkerJoin),
    Raw(JoinHandle<EffectObservation>),
}

struct CoordinatorDropNotify(Shared);

impl Drop for CoordinatorDropNotify {
    fn drop(&mut self) {
        self.0
            .coordinator_future_dropped
            .store(true, Ordering::SeqCst);
        self.0.state_updates.send_modify(|_| {});
    }
}

enum Command {
    Admit {
        role: OwnerRole,
        reply: oneshot::Sender<Result<(), Refusal>>,
    },
    AcceptHandoff {
        reply: oneshot::Sender<Result<(), Refusal>>,
        initiator_ack: Option<oneshot::Sender<Result<(), Refusal>>>,
        reply_sent: Option<oneshot::Sender<()>>,
    },
    Cancel {
        role: OwnerRole,
        reply: oneshot::Sender<Result<(), Refusal>>,
    },
    Retire {
        role: OwnerRole,
        reply: oneshot::Sender<Result<(), Refusal>>,
    },
    RecordOutcome {
        role: OwnerRole,
        observation: EffectObservation,
        reply: oneshot::Sender<Result<(), RecordError>>,
    },
    ObservePublication {
        role: OwnerRole,
        publication: Publication,
        reply: oneshot::Sender<Result<(), PublishError>>,
    },
    OwnerDropped {
        role: OwnerRole,
    },
    PauseCoordinator {
        entered: oneshot::Sender<()>,
        release: oneshot::Receiver<()>,
    },
    PanicForTest,
}

async fn run_supervisor(
    mut commands: mpsc::Receiver<Command>,
    mut worker: WorkerJoin,
    shared: Shared,
    outcome_capacity: usize,
    mut join_apply_gate: Option<JoinApplyGate>,
) {
    let mut task_done = false;
    let mut commands_open = true;
    loop {
        if task_done && !commands_open {
            break;
        }
        tokio::select! {
            command = commands.recv(), if commands_open => {
                match command {
                    Some(command) => {
                        process_command(command, &shared, &worker, outcome_capacity).await;
                    }
                    None => {
                        commands_open = false;
                        worker.request_abort();
                    }
                }
            }
            joined = worker.join(), if !task_done => {
                task_done = true;
                worker.shared.worker_join_observed.store(true, Ordering::SeqCst);
                worker.shared.worker_result_unobserved.store(false, Ordering::SeqCst);
                worker.shared.worker_result_disposition.store(
                    WorkerResultDisposition::ObservedUnrecorded as u8,
                    Ordering::SeqCst,
                );
                worker.handle.take();
                if let Some(gate) = join_apply_gate.take() {
                    let _ = gate.result_observed.send(());
                    let _ = gate.release_application.await;
                }
                let mut state = shared.state.lock().await;
                apply_worker_join(&mut state, joined, outcome_capacity, &shared);
                worker.shared.worker_result_disposition.store(
                    WorkerResultDisposition::Recorded as u8,
                    Ordering::SeqCst,
                );
                publish(&shared, &state);
            }
        }
        if shared.overflow.load(Ordering::SeqCst) {
            let mut state = shared.state.lock().await;
            state.control_overflow = true;
            state.refusal_closed = true;
            state.participation_allowed = false;
            publish(&shared, &state);
        }
    }
}

async fn process_command(
    command: Command,
    shared: &Shared,
    worker: &WorkerJoin,
    outcome_capacity: usize,
) {
    if let Command::PauseCoordinator { entered, release } = command {
        let _ = entered.send(());
        let _ = release.await;
        return;
    }

    let mut state = shared.state.lock().await;
    state.control_overflow |= shared.overflow.load(Ordering::SeqCst);
    if shared.current_owner.load(Ordering::SeqCst) == OwnerRole::Lost.code() {
        state.owner = OwnerRole::Lost;
        state.refusal_closed = true;
        state.participation_allowed = false;
    }
    match command {
        Command::Admit { role, reply } => {
            let result = if shared
                .current_owner
                .compare_exchange(role.code(), role.code(), Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                state.refuse(role)
            } else {
                Err(if state.control_overflow {
                    Refusal::CapacityUncertain
                } else {
                    Refusal::NotCurrentOwner
                })
            };
            if result.is_ok() {
                state.protected_admissions = state.protected_admissions.saturating_add(1);
            }
            let _ = reply.send(result);
        }
        Command::AcceptHandoff {
            reply,
            initiator_ack,
            reply_sent,
        } => {
            let result = if state.owner == OwnerRole::Initiator
                && !state.operation_cancelled
                && !state.operation_retired
                && shared
                    .current_owner
                    .compare_exchange(
                        OwnerRole::Initiator.code(),
                        OwnerRole::Supervisor.code(),
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    )
                    .is_ok()
            {
                state.owner = OwnerRole::Supervisor;
                Ok(())
            } else {
                Err(Refusal::NotCurrentOwner)
            };
            if result.is_ok() {
                if reply.send(Ok(())).is_err() {
                    state.owner = OwnerRole::Lost;
                    state.refusal_closed = true;
                    state.participation_allowed = false;
                    shared
                        .current_owner
                        .store(OwnerRole::Lost.code(), Ordering::SeqCst);
                    if let Some(ack) = initiator_ack {
                        let _ = ack.send(Err(Refusal::SupervisorLost));
                    }
                } else if let Some(ack) = initiator_ack {
                    if let Some(reply_sent) = reply_sent {
                        let _ = reply_sent.send(());
                    }
                    let _ = ack.send(Ok(()));
                } else if let Some(reply_sent) = reply_sent {
                    let _ = reply_sent.send(());
                }
            } else {
                let _ = reply.send(result);
                if let Some(ack) = initiator_ack {
                    let _ = ack.send(result);
                }
            }
        }
        Command::Cancel { role, reply } => {
            let result = if state.owner == role && !state.operation_retired {
                state.operation_cancelled = true;
                state.refusal_closed = true;
                state.participation_allowed = false;
                worker.request_abort();
                Ok(())
            } else {
                Err(Refusal::NotCurrentOwner)
            };
            let _ = reply.send(result);
        }
        Command::Retire { role, reply } => {
            let result = if state.owner != role {
                Err(Refusal::NotCurrentOwner)
            } else if state.operation_cancelled {
                Err(Refusal::OperationCancelled)
            } else if state.worker_status != WorkerStatus::Completed
                || !state.effect_is_known_and_consistent()
                || state.publication != Publication::Acknowledged
                || state.control_overflow
            {
                Err(Refusal::EffectUnresolved)
            } else {
                state.operation_retired = true;
                state.refusal_closed = true;
                state.participation_allowed = false;
                Ok(())
            };
            let _ = reply.send(result);
        }
        Command::RecordOutcome {
            role,
            observation,
            reply,
        } => {
            let result = if state.owner != role {
                Err(RecordError::Refused(Refusal::NotCurrentOwner, observation))
            } else if state.observations.len() >= outcome_capacity
                || (state.worker_status == WorkerStatus::Running
                    && state.observations.len() >= outcome_capacity.saturating_sub(1))
            {
                state.outcome_overflow = true;
                Err(RecordError::Capacity(observation))
            } else {
                add_observation(&mut state, observation);
                Ok(())
            };
            if matches!(result, Err(RecordError::Capacity(_))) {
                state.refusal_closed = true;
                state.participation_allowed = false;
            }
            let _ = reply.send(result);
        }
        Command::ObservePublication {
            role,
            publication,
            reply,
        } => {
            let result = if state.owner != role && role != OwnerRole::Initiator {
                Err(PublishError::InvalidTransition(publication))
            } else {
                apply_publication(&mut state, publication)
                    .map_err(|_| PublishError::InvalidTransition(publication))
            };
            let _ = reply.send(result);
        }
        Command::OwnerDropped { role } => {
            if state.owner == role && !state.operation_retired {
                state.owner = OwnerRole::Lost;
                state.refusal_closed = true;
                state.participation_allowed = false;
                shared
                    .current_owner
                    .store(OwnerRole::Lost.code(), Ordering::SeqCst);
            }
        }
        Command::PanicForTest => panic!("synthetic supervisor panic"),
        Command::PauseCoordinator { .. } => unreachable!(),
    }
    state.control_overflow |= shared.overflow.load(Ordering::SeqCst);
    publish(shared, &state);
}

fn apply_worker_join(
    state: &mut Snapshot,
    joined: Result<EffectObservation, JoinError>,
    outcome_capacity: usize,
    shared: &Shared,
) {
    state.worker_completed = true;
    match joined {
        Ok(observation) => {
            state.worker_status = WorkerStatus::Completed;
            if state.observations.len() < outcome_capacity {
                add_observation(state, observation);
            } else {
                state.outcome_overflow = true;
                shared.overflow.store(true, Ordering::SeqCst);
            }
        }
        Err(error) if error.is_cancelled() => {
            state.worker_status = WorkerStatus::Cancelled;
            state.publication = make_uncertain(state.publication);
            state.outcome_unknown = true;
            if state.observations.len() < outcome_capacity {
                add_observation(state, EffectObservation::Unknown);
            } else {
                state.outcome_overflow = true;
                shared.overflow.store(true, Ordering::SeqCst);
            }
        }
        Err(error) if error.is_panic() => {
            state.worker_status = WorkerStatus::Panicked;
            state.publication = make_uncertain(state.publication);
            state.outcome_unknown = true;
            if state.observations.len() < outcome_capacity {
                add_observation(state, EffectObservation::Unknown);
            } else {
                state.outcome_overflow = true;
                shared.overflow.store(true, Ordering::SeqCst);
            }
        }
        Err(_) => {
            state.worker_status = WorkerStatus::Panicked;
            state.publication = make_uncertain(state.publication);
            state.outcome_unknown = true;
            state.outcome_overflow = true;
            shared.overflow.store(true, Ordering::SeqCst);
        }
    }
    state.refusal_closed = true;
    state.participation_allowed = false;
}

fn add_observation(state: &mut Snapshot, observation: EffectObservation) {
    state.outcome_unknown |= observation == EffectObservation::Unknown;
    if let EffectObservation::Known(value) = observation {
        if state
            .observations
            .iter()
            .any(|previous| matches!(previous, EffectObservation::Known(old) if *old != value))
        {
            state.outcome_conflict = true;
        }
    }
    state.observations.push(observation);
    state.refusal_closed = true;
    state.participation_allowed = false;
}

fn apply_publication(state: &mut Snapshot, next: Publication) -> Result<(), ()> {
    state.publication = match (state.publication, next) {
        (Publication::Pending, Publication::Pending) => Publication::Pending,
        (Publication::Pending, Publication::Visible) => Publication::Visible,
        (Publication::Visible, Publication::Visible) => Publication::Visible,
        (Publication::Visible, Publication::Acknowledged) => Publication::Acknowledged,
        (Publication::Acknowledged, Publication::Acknowledged) => Publication::Acknowledged,
        (Publication::Pending | Publication::Visible, Publication::Failed) => Publication::Failed,
        (
            Publication::Pending | Publication::Visible | Publication::Acknowledged,
            Publication::Uncertain,
        ) => Publication::Uncertain,
        (Publication::Failed, _) | (Publication::Uncertain, _) => return Err(()),
        (Publication::Acknowledged, Publication::Failed) => Publication::Uncertain,
        _ => return Err(()),
    };
    state.refusal_closed = true;
    state.participation_allowed = false;
    Ok(())
}

fn make_uncertain(publication: Publication) -> Publication {
    if matches!(publication, Publication::Failed | Publication::Uncertain) {
        publication
    } else {
        Publication::Uncertain
    }
}

fn publish(shared: &Shared, state: &Snapshot) {
    let mut snapshot = state.clone();
    snapshot.control_overflow |= shared.overflow.load(Ordering::SeqCst);
    snapshot.supervisor_lost |= shared.supervisor_lost.load(Ordering::SeqCst);
    if shared.current_owner.load(Ordering::SeqCst) == OwnerRole::Lost.code() {
        snapshot.owner = OwnerRole::Lost;
        snapshot.refusal_closed = true;
        snapshot.participation_allowed = false;
    }
    let _ = shared.state_updates.send(snapshot);
}

struct WorkerJoin {
    handle: Option<JoinHandle<EffectObservation>>,
    abort: tokio::task::AbortHandle,
    shared: Shared,
}

impl WorkerJoin {
    fn new(handle: JoinHandle<EffectObservation>, shared: Shared) -> Self {
        let abort = handle.abort_handle();
        Self {
            handle: Some(handle),
            abort,
            shared,
        }
    }

    fn request_abort(&self) {
        self.shared
            .worker_abort_requested
            .store(true, Ordering::SeqCst);
        self.abort.abort();
    }

    async fn join(&mut self) -> Result<EffectObservation, JoinError> {
        self.handle
            .as_mut()
            .expect("worker join handle present")
            .await
    }
}

impl Drop for WorkerJoin {
    fn drop(&mut self) {
        if self.handle.is_some() {
            self.shared
                .worker_result_unobserved
                .store(true, Ordering::SeqCst);
            self.shared
                .worker_result_disposition
                .store(WorkerResultDisposition::NotObserved as u8, Ordering::SeqCst);
            self.request_abort();
        }
    }
}
