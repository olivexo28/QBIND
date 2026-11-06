//! Non-wired, in-process A33-F1 / E27 ownership prototype.
//!
//! This test-support component exposes only synthetic protected-operation
//! admission. It has no production consensus, signer, storage, network,
//! startup, or restore capabilities.

use std::future::Future;
use std::sync::{
    atomic::{AtomicBool, Ordering},
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
}

#[derive(Clone)]
struct ReadShared {
    state: Arc<Mutex<Snapshot>>,
    state_updates: watch::Sender<Snapshot>,
    overflow: Arc<AtomicBool>,
    supervisor_lost: Arc<AtomicBool>,
}

impl Shared {
    fn read_shared(&self) -> ReadShared {
        ReadShared {
            state: self.state.clone(),
            state_updates: self.state_updates.clone(),
            overflow: self.overflow.clone(),
            supervisor_lost: self.supervisor_lost.clone(),
        }
    }
}

pub(crate) struct OperationOwner {
    commands: mpsc::Sender<Command>,
    shared: Shared,
    role: OwnerRole,
}

impl OperationOwner {
    pub(crate) fn role(&self) -> OwnerRole {
        self.role
    }

    pub(crate) fn reader(&self) -> StateReader {
        StateReader {
            updates: self.shared.state_updates.subscribe(),
            shared: self.shared.read_shared(),
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
        if self
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
        let (reply, result) = oneshot::channel();
        self.commands
            .send(Command::AcceptHandoff {
                reply,
                initiator_ack: self.ack.take(),
            })
            .await
            .map_err(|_| Refusal::SupervisorLost)?;
        result.await.unwrap_or(Err(Refusal::SupervisorLost))?;
        Ok(OperationOwner {
            commands: self.commands.clone(),
            shared: self.shared.clone(),
            role: OwnerRole::Supervisor,
        })
    }
}

pub(crate) struct StateReader {
    updates: watch::Receiver<Snapshot>,
    shared: ReadShared,
}

impl StateReader {
    pub(crate) async fn snapshot(&self) -> Snapshot {
        let mut state = self.shared.state.lock().await.clone();
        state.control_overflow |= self.shared.overflow.load(Ordering::SeqCst);
        state.supervisor_lost |= self.shared.supervisor_lost.load(Ordering::SeqCst);
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
    shared: ReadShared,
}

impl SupervisorTask {
    pub(crate) async fn join(mut self) -> Result<(), SupervisorJoinError> {
        let mut join = self.join.take().expect("supervisor join handle present");
        match timeout(WATCHDOG, &mut join).await {
            Ok(result) => {
                if result.is_err() {
                    self.shared.supervisor_lost.store(true, Ordering::SeqCst);
                }
                result.map_err(SupervisorJoinError::Task)
            }
            Err(_) => {
                join.abort();
                self.shared.supervisor_lost.store(true, Ordering::SeqCst);
                match timeout(WATCHDOG, &mut join).await {
                    Ok(Err(error)) => Err(SupervisorJoinError::WatchdogAborted(error)),
                    Ok(Ok(())) => Err(SupervisorJoinError::CompletedAfterWatchdog),
                    Err(_) => Err(SupervisorJoinError::WatchdogUnresolved),
                }
            }
        }
    }

    pub(crate) async fn abort_and_join(mut self) -> Result<(), SupervisorJoinError> {
        let mut join = self.join.take().expect("supervisor join handle present");
        join.abort();
        self.shared.supervisor_lost.store(true, Ordering::SeqCst);
        match timeout(WATCHDOG, &mut join).await {
            Ok(Err(error)) => Err(SupervisorJoinError::Task(error)),
            Ok(Ok(())) => Ok(()),
            Err(_) => Err(SupervisorJoinError::WatchdogUnresolved),
        }
    }
}

impl Drop for SupervisorTask {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            self.shared.supervisor_lost.store(true, Ordering::SeqCst);
            join.abort();
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
    let shared = Shared {
        state,
        state_updates,
        overflow,
        supervisor_lost,
    };

    let publisher = MockPublisher {
        commands: commands.clone(),
        shared: shared.clone(),
    };
    let worker = tokio::spawn(work(publisher));
    let supervisor_shared = shared.clone();
    let join = tokio::spawn(async move {
        run_supervisor(receiver, worker, supervisor_shared, outcome_capacity).await;
    });

    (
        OperationOwner {
            commands,
            shared: shared.clone(),
            role: OwnerRole::Initiator,
        },
        SupervisorTask {
            join: Some(join),
            shared: shared.read_shared(),
        },
    )
}

enum Command {
    Admit {
        role: OwnerRole,
        reply: oneshot::Sender<Result<(), Refusal>>,
    },
    AcceptHandoff {
        reply: oneshot::Sender<Result<(), Refusal>>,
        initiator_ack: Option<oneshot::Sender<Result<(), Refusal>>>,
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
    PanicForTest,
}

async fn run_supervisor(
    mut commands: mpsc::Receiver<Command>,
    worker: JoinHandle<EffectObservation>,
    shared: Shared,
    outcome_capacity: usize,
) {
    let mut worker = WorkerJoin::new(worker);
    let worker_abort = worker.abort.clone();
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
                        process_command(command, &shared, &worker_abort, outcome_capacity).await;
                    }
                    None => {
                        commands_open = false;
                        worker_abort.abort();
                    }
                }
            }
            joined = worker.join(), if !task_done => {
                task_done = true;
                worker.handle.take();
                let mut state = shared.state.lock().await;
                apply_worker_join(&mut state, joined, outcome_capacity, &shared);
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
    worker_abort: &tokio::task::AbortHandle,
    outcome_capacity: usize,
) {
    let mut state = shared.state.lock().await;
    state.control_overflow |= shared.overflow.load(Ordering::SeqCst);
    match command {
        Command::Admit { role, reply } => {
            let result = state.refuse(role);
            if result.is_ok() {
                state.protected_admissions = state.protected_admissions.saturating_add(1);
            }
            let _ = reply.send(result);
        }
        Command::AcceptHandoff {
            reply,
            initiator_ack,
        } => {
            let result = if state.owner == OwnerRole::Initiator
                && !state.operation_cancelled
                && !state.operation_retired
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
                    if let Some(ack) = initiator_ack {
                        let _ = ack.send(Err(Refusal::SupervisorLost));
                    }
                } else if let Some(ack) = initiator_ack {
                    let _ = ack.send(Ok(()));
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
                worker_abort.abort();
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
            }
        }
        Command::PanicForTest => panic!("synthetic supervisor panic"),
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
    let _ = shared.state_updates.send(snapshot);
}

struct WorkerJoin {
    handle: Option<JoinHandle<EffectObservation>>,
    abort: tokio::task::AbortHandle,
}

impl WorkerJoin {
    fn new(handle: JoinHandle<EffectObservation>) -> Self {
        let abort = handle.abort_handle();
        Self {
            handle: Some(handle),
            abort,
        }
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
            self.abort.abort();
        }
    }
}
