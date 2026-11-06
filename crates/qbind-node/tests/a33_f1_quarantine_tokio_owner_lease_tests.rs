//! Test-only Tokio owner/lease lifecycle harness for A33-F1 / E27.
//! Mock publication and synthetic state only; no production component is wired.

use std::collections::BTreeMap;
use std::future::Future;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;
use tokio::time::timeout;

const WATCHDOG: Duration = Duration::from_secs(3);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Owner {
    Initiator,
    Supervisor,
    Lost,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Publication {
    None,
    Pending,
    Visible,
    Acknowledged,
    Failed,
    Uncertain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Observed,
    Unknown,
}

#[derive(Debug)]
struct SyntheticState {
    owner: Owner,
    owner_task_terminated: bool,
    handoff_offered: bool,
    handoff_accepted: bool,
    operation_cancelled: bool,
    operation_retired: bool,
    application_task_completed: bool,
    cleanup_observed: bool,
    refusal_closed: bool,
    participation_allowed: bool,
    publication: Publication,
    work_pending: bool,
    worker_completed: bool,
    effect_known: bool,
    outcomes: Vec<Outcome>,
    protected_mutations: usize,
}

impl SyntheticState {
    fn new() -> Self {
        Self {
            owner: Owner::Initiator,
            owner_task_terminated: false,
            handoff_offered: false,
            handoff_accepted: false,
            operation_cancelled: false,
            operation_retired: false,
            application_task_completed: false,
            cleanup_observed: false,
            refusal_closed: true,
            participation_allowed: false,
            publication: Publication::None,
            work_pending: false,
            worker_completed: true,
            effect_known: true,
            outcomes: Vec::new(),
            protected_mutations: 0,
        }
    }

    fn offer_handoff(&mut self) -> Result<(), &'static str> {
        if self.owner != Owner::Initiator || self.operation_cancelled {
            return Err("handoff requires active initiator ownership");
        }
        self.handoff_offered = true;
        Ok(())
    }

    fn accept_handoff(&mut self) -> Result<(), &'static str> {
        if self.owner != Owner::Initiator || !self.handoff_offered {
            return Err("supervisor ownership transferred before acceptance");
        }
        self.owner = Owner::Supervisor;
        self.handoff_accepted = true;
        Ok(())
    }

    fn cancel_operation(&mut self) {
        self.operation_cancelled = true;
        self.refusal_closed = true;
        self.participation_allowed = false;
    }

    fn observe_publication(&mut self, publication: Publication) -> Result<(), &'static str> {
        let next = match (self.publication, publication) {
            (Publication::None, Publication::Pending) => Publication::Pending,
            (Publication::Pending, Publication::Pending)
            | (Publication::Visible, Publication::Visible)
            | (Publication::Acknowledged, Publication::Acknowledged) => self.publication,
            (Publication::Pending, Publication::Visible) => Publication::Visible,
            (Publication::Visible, Publication::Acknowledged) => Publication::Acknowledged,
            (Publication::Pending | Publication::Visible, Publication::Failed) => {
                Publication::Failed
            }
            (
                Publication::Pending | Publication::Visible | Publication::Acknowledged,
                Publication::Uncertain,
            ) => Publication::Uncertain,
            (Publication::Acknowledged, Publication::Visible) => Publication::Acknowledged,
            (Publication::Acknowledged, Publication::Failed) => Publication::Uncertain,
            (Publication::Failed, _) => {
                return Err("publication attempt failed and is terminal");
            }
            (Publication::Uncertain, _) => {
                return Err("publication attempt is uncertain and terminal");
            }
            (_, Publication::Acknowledged) => {
                return Err("acknowledgment requires known publication visibility");
            }
            (_, Publication::Visible) => {
                return Err("visibility requires a pending publication attempt");
            }
            (_, Publication::Failed | Publication::Uncertain) => {
                return Err("failure or uncertainty requires a pending attempt");
            }
            (Publication::None, Publication::None) => Publication::None,
            (_, Publication::None | Publication::Pending) => {
                return Err("publication observation cannot move backward");
            }
        };
        self.publication = next;
        self.refusal_closed = true;
        Ok(())
    }

    fn begin_work(&mut self) -> Result<(), &'static str> {
        if self.work_pending || !self.effect_known {
            return Err("cannot admit work while a prior effect is unresolved");
        }
        self.work_pending = true;
        self.worker_completed = false;
        self.effect_known = false;
        Ok(())
    }

    fn observe_outcome(&mut self, outcome: Outcome) -> Result<(), &'static str> {
        if !self.work_pending || self.worker_completed {
            return Err("worker completion was already observed or not admitted");
        }
        self.work_pending = false;
        self.worker_completed = true;
        self.effect_known = outcome != Outcome::Unknown;
        self.outcomes.push(outcome);
        self.refusal_closed = true;
        Ok(())
    }

    fn observe_owner_task_termination(&mut self) -> Result<(), &'static str> {
        if !matches!(self.owner, Owner::Initiator | Owner::Supervisor) {
            return Err("terminated task did not own refusal responsibility");
        }
        self.owner_task_terminated = true;
        Ok(())
    }

    fn observe_application_task_completion(&mut self) -> Result<(), &'static str> {
        if self.operation_cancelled || self.owner_task_terminated {
            return Err("cancelled or terminated owner cannot complete operation");
        }
        self.application_task_completed = true;
        Ok(())
    }

    fn observe_cleanup_completion(&mut self) -> Result<(), &'static str> {
        if !self.application_task_completed {
            return Err("cleanup cannot precede observed application completion");
        }
        self.cleanup_observed = true;
        Ok(())
    }

    fn retire_operation(&mut self, actor: Owner) -> Result<(), &'static str> {
        if actor != self.owner || !matches!(actor, Owner::Initiator | Owner::Supervisor) {
            return Err("operation retirement requires current refusal owner");
        }
        if self.operation_cancelled {
            return Err("cancelled operation cannot retire as successful");
        }
        if !self.application_task_completed || !self.cleanup_observed {
            return Err("operation retirement requires observed completion and cleanup");
        }
        if self.publication != Publication::Acknowledged
            || self.work_pending
            || !self.worker_completed
            || !self.effect_known
        {
            return Err("operation retirement requires acknowledged, resolved effects");
        }
        self.operation_retired = true;
        self.refusal_closed = true;
        self.participation_allowed = false;
        Ok(())
    }

    fn record_late_outcome(&mut self, actor: Owner, outcome: Outcome) -> Result<(), &'static str> {
        if !self.operation_retired {
            return Err("late outcome recording requires retired operation");
        }
        if actor != self.owner || !matches!(actor, Owner::Initiator | Owner::Supervisor) {
            return Err("late outcome requires current refusal owner");
        }
        self.outcomes.push(outcome);
        self.refusal_closed = true;
        self.participation_allowed = false;
        Ok(())
    }

    fn lose_owner(&mut self) -> Result<(), &'static str> {
        if !self.owner_task_terminated {
            return Err("ownership loss requires observed owner task termination");
        }
        self.owner = Owner::Lost;
        if self.publication == Publication::Pending {
            self.publication = Publication::Uncertain;
        }
        self.refusal_closed = true;
        self.participation_allowed = false;
        Ok(())
    }

    fn validate_refusal_closed(&self) -> Result<(), &'static str> {
        if self.participation_allowed || !self.refusal_closed {
            return Err("refusal latch reopened");
        }
        Ok(())
    }

    fn admit_protected_mutation(&mut self, actor: Owner) -> Result<(), &'static str> {
        if self.operation_cancelled {
            return Err("operation cancellation forbids protected mutation");
        }
        if self.operation_retired {
            return Err("completed operation authority is retired");
        }
        if actor != self.owner || !matches!(actor, Owner::Initiator | Owner::Supervisor) {
            return Err("mutation actor does not own refusal responsibility");
        }
        if self.owner_task_terminated {
            return Err("ownership loss transition is missing after task termination");
        }
        if self.publication != Publication::Acknowledged {
            return Err("protected mutation requires acknowledged publication");
        }
        if self.work_pending || !self.worker_completed {
            return Err("protected mutation blocked by outstanding work");
        }
        if !self.effect_known {
            return Err("protected mutation blocked by unresolved external effect");
        }
        self.protected_mutations += 1;
        Ok(())
    }

    fn reopen(&mut self) -> Result<(), &'static str> {
        Err("no modeled transition may reopen participation")
    }
}

type TaskResult = Result<(), &'static str>;

#[derive(Debug, PartialEq, Eq)]
enum TaskTermination {
    Cancelled,
    Completed(TaskResult),
}

#[derive(Default)]
struct Tasks {
    handles: BTreeMap<&'static str, JoinHandle<TaskResult>>,
}

impl Tasks {
    fn spawn<F>(&mut self, name: &'static str, future: F)
    where
        F: Future<Output = TaskResult> + Send + 'static,
    {
        assert!(self.handles.insert(name, tokio::spawn(future)).is_none());
    }

    async fn observe(&mut self, name: &'static str) -> Result<TaskResult, String> {
        let mut handle = self.handles.remove(name).ok_or("known task")?;
        match timeout(WATCHDOG, &mut handle).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(error)) => Err(format!("{name} join failed: {error}")),
            Err(_) => {
                handle.abort();
                match timeout(WATCHDOG, &mut handle).await {
                    Ok(Err(error)) if error.is_cancelled() => {
                        Err(format!("{name} exceeded watchdog and was aborted"))
                    }
                    Ok(Ok(_)) => Err(format!("{name} completed after watchdog")),
                    Ok(Err(error)) => Err(format!("{name} cleanup join failed: {error}")),
                    Err(_) => Err(format!("{name} failed to join after abort")),
                }
            }
        }
    }

    async fn abort_and_observe(&mut self, name: &'static str) -> Result<TaskTermination, String> {
        let mut handle = self.handles.remove(name).ok_or("known task")?;
        handle.abort();
        match timeout(WATCHDOG, &mut handle).await {
            Err(_) => {
                handle.abort();
                match timeout(WATCHDOG, &mut handle).await {
                    Ok(Err(error)) if error.is_cancelled() => Ok(TaskTermination::Cancelled),
                    Ok(Ok(result)) => Ok(TaskTermination::Completed(result)),
                    Ok(Err(error)) => Err(format!("task join failed: {error}")),
                    Err(_) => Err("aborted task did not join after second watchdog".into()),
                }
            }
            Ok(Err(error)) if error.is_cancelled() => Ok(TaskTermination::Cancelled),
            Ok(Err(error)) => Err(format!("task join failed unexpectedly: {error}")),
            Ok(Ok(result)) => Ok(TaskTermination::Completed(result)),
        }
    }

    async fn abort_owner_and_observe_loss(
        &mut self,
        name: &'static str,
        state: &Mutex<SyntheticState>,
    ) -> Result<(), String> {
        let termination = self.abort_and_observe(name).await?;
        if termination != TaskTermination::Cancelled {
            return Err(format!(
                "{name} termination was not observed as cancellation: {termination:?}"
            ));
        }
        let mut state = lock_state(state).await?;
        state
            .observe_owner_task_termination()
            .map_err(str::to_owned)?;
        state.lose_owner().map_err(str::to_owned)
    }

    async fn cleanup(&mut self) -> Result<(), String> {
        for handle in self.handles.values() {
            handle.abort();
        }
        let handles = std::mem::take(&mut self.handles);
        let mut errors = Vec::new();
        for (name, mut handle) in handles {
            match timeout(WATCHDOG, &mut handle).await {
                Err(_) => {
                    handle.abort();
                    match timeout(WATCHDOG, &mut handle).await {
                        Ok(Err(error)) if error.is_cancelled() => {}
                        Ok(Ok(_)) => {
                            errors.push(format!("{name} completed after cleanup watchdog"))
                        }
                        Ok(Err(error)) => {
                            errors.push(format!("{name} cleanup join failed: {error}"))
                        }
                        Err(_) => errors.push(format!("{name} did not join after abort")),
                    }
                }
                Ok(Err(error)) if error.is_cancelled() => {}
                Ok(Err(error)) => errors.push(format!("{name} join failed: {error}")),
                Ok(Ok(Err(error))) => errors.push(format!("{name} returned error: {error}")),
                Ok(Ok(Ok(()))) => {}
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

impl Drop for Tasks {
    fn drop(&mut self) {
        for handle in self.handles.values() {
            handle.abort();
        }
    }
}

async fn recv<T>(receiver: &mut mpsc::UnboundedReceiver<T>) -> Result<T, String> {
    timeout(WATCHDOG, receiver.recv())
        .await
        .map_err(|_| "channel watchdog expired".to_owned())?
        .ok_or_else(|| "channel closed before expected event".to_owned())
}

async fn lock_state(
    state: &Mutex<SyntheticState>,
) -> Result<tokio::sync::MutexGuard<'_, SyntheticState>, String> {
    timeout(WATCHDOG, state.lock())
        .await
        .map_err(|_| "state lock watchdog expired".to_owned())
}

fn require_completed_authority_refusal(
    state: &mut SyntheticState,
    actor: Owner,
) -> Result<(), &'static str> {
    match state.admit_protected_mutation(actor) {
        Err("completed operation authority is retired") => Ok(()),
        Err(_) => Err("mutation refused for a reason other than operation retirement"),
        Ok(()) => Err("retirement check detected mutation admitted after completion"),
    }
}

#[tokio::test]
async fn cancellation_before_acceptance_does_not_transfer_responsibility() {
    let state = std::sync::Arc::new(Mutex::new(SyntheticState::new()));
    state.lock().await.offer_handoff().unwrap();
    let (offer_tx, mut offer_rx) = mpsc::unbounded_channel::<()>();
    let (ready_tx, ready_rx) = mpsc::unbounded_channel::<()>();
    let (decision_tx, decision_rx) = oneshot::channel::<bool>();
    let (accepted_tx, accepted_rx) = oneshot::channel::<()>();
    let mut tasks = Tasks::default();

    tasks.spawn("initiator", async move {
        offer_tx.send(()).map_err(|_| "supervisor unavailable")?;
        accepted_rx.await.map_err(|_| "handoff not accepted")?;
        Ok(())
    });
    let supervisor_state = state.clone();
    tasks.spawn("supervisor", async move {
        offer_rx.recv().await.ok_or("offer missing")?;
        ready_tx.send(()).map_err(|_| "test receiver unavailable")?;
        if decision_rx.await.map_err(|_| "decision missing")? {
            supervisor_state.lock().await.accept_handoff()?;
            accepted_tx.send(()).map_err(|_| "initiator unavailable")?;
        }
        Ok(())
    });

    let scenario = async {
        let mut ready = ready_rx;
        recv(&mut ready).await?;
        tasks
            .abort_owner_and_observe_loss("initiator", &state)
            .await
            .map_err(|error| error.to_string())?;
        {
            let mut state = lock_state(&state).await?;
            if state.handoff_accepted {
                return Err("responsibility transferred without acceptance".into());
            }
            if state.admit_protected_mutation(Owner::Supervisor).is_ok() {
                return Err("mutation admitted without accepted handoff".into());
            }
        }
        decision_tx
            .send(false)
            .map_err(|_| "supervisor ended before refusal".to_owned())?;
        let supervisor = tasks
            .observe("supervisor")
            .await
            .map_err(|error| format!("supervisor join failed: {error}"))?;
        supervisor.map_err(str::to_owned)?;
        Ok::<(), String>(())
    }
    .await;
    let cleanup = tasks.cleanup().await;
    assert!(cleanup.is_ok(), "{cleanup:?}");
    assert!(scenario.is_ok(), "{scenario:?}");
    let state = state.lock().await;
    assert_eq!(state.owner, Owner::Lost);
    assert!(!state.handoff_accepted);
    assert!(state.refusal_closed);
    assert_eq!(state.protected_mutations, 0);
}

#[tokio::test]
async fn accepted_supervisor_outlives_initiator_and_observes_outstanding_result() {
    let state = std::sync::Arc::new(Mutex::new(SyntheticState::new()));
    state.lock().await.begin_work().unwrap();
    state.lock().await.offer_handoff().unwrap();
    let (offer_tx, mut offer_rx) = mpsc::unbounded_channel::<()>();
    let (accept_tx, accept_rx) = oneshot::channel::<()>();
    let (accepted_tx, accepted_rx) = mpsc::unbounded_channel::<()>();
    let (result_tx, result_rx) = oneshot::channel::<Outcome>();
    let (observed_tx, observed_rx) = mpsc::unbounded_channel::<Outcome>();
    let mut tasks = Tasks::default();

    tasks.spawn("initiator", async move {
        offer_tx.send(()).map_err(|_| "supervisor unavailable")?;
        accept_rx.await.map_err(|_| "handoff refused")?;
        Ok(())
    });
    let supervisor_state = state.clone();
    tasks.spawn("supervisor", async move {
        offer_rx.recv().await.ok_or("offer missing")?;
        supervisor_state.lock().await.accept_handoff()?;
        accepted_tx
            .send(())
            .map_err(|_| "test receiver unavailable")?;
        let outcome = result_rx.await.map_err(|_| "outstanding result missing")?;
        supervisor_state.lock().await.observe_outcome(outcome)?;
        observed_tx
            .send(outcome)
            .map_err(|_| "test receiver unavailable")?;
        Ok(())
    });

    let scenario = async {
        let mut accepted = accepted_rx;
        recv(&mut accepted).await?;
        accept_tx
            .send(())
            .map_err(|_| "initiator ended early".to_owned())?;
        let initiator = tasks
            .observe("initiator")
            .await
            .map_err(|error| format!("initiator join failed: {error}"))?;
        initiator.map_err(str::to_owned)?;
        result_tx
            .send(Outcome::Observed)
            .map_err(|_| "supervisor ended before result".to_owned())?;
        let mut observed = observed_rx;
        if recv(&mut observed).await? != Outcome::Observed {
            return Err("supervisor did not report the observed result".into());
        }
        let supervisor = tasks
            .observe("supervisor")
            .await
            .map_err(|error| format!("supervisor join failed: {error}"))?;
        supervisor.map_err(str::to_owned)?;
        let state = lock_state(&state).await?;
        if state.owner != Owner::Supervisor
            || state.work_pending
            || !state.refusal_closed
            || state.operation_cancelled
        {
            return Err("supervisor did not retain and discharge responsibility".into());
        }
        if state.participation_allowed {
            return Err("initiator task end reopened participation".into());
        }
        Ok::<(), String>(())
    }
    .await;
    let cleanup = tasks.cleanup().await;
    assert!(cleanup.is_ok(), "{cleanup:?}");
    assert!(scenario.is_ok(), "{scenario:?}");
}

#[tokio::test]
async fn operation_cancellation_after_handoff_blocks_supervisor_mutation() {
    let state = std::sync::Arc::new(Mutex::new(SyntheticState::new()));
    {
        let mut state = state.lock().await;
        state.begin_work().unwrap();
        state.offer_handoff().unwrap();
    }
    let (offer_tx, mut offer_rx) = mpsc::unbounded_channel::<()>();
    let (accept_tx, accept_rx) = oneshot::channel::<()>();
    let (accepted_tx, accepted_rx) = mpsc::unbounded_channel::<()>();
    let (result_tx, result_rx) = oneshot::channel::<Outcome>();
    let (checked_tx, checked_rx) = mpsc::unbounded_channel::<Result<(), &'static str>>();
    let mut tasks = Tasks::default();

    tasks.spawn("initiator", async move {
        offer_tx.send(()).map_err(|_| "supervisor unavailable")?;
        accept_rx.await.map_err(|_| "handoff refused")?;
        Ok(())
    });
    let supervisor_state = state.clone();
    tasks.spawn("supervisor", async move {
        offer_rx.recv().await.ok_or("offer missing")?;
        supervisor_state.lock().await.accept_handoff()?;
        accepted_tx
            .send(())
            .map_err(|_| "test receiver unavailable")?;
        let outcome = result_rx.await.map_err(|_| "outcome missing")?;
        supervisor_state.lock().await.observe_outcome(outcome)?;
        let result = supervisor_state
            .lock()
            .await
            .admit_protected_mutation(Owner::Supervisor);
        checked_tx
            .send(result)
            .map_err(|_| "test receiver unavailable")?;
        Ok(())
    });

    let scenario = async {
        let mut accepted = accepted_rx;
        recv(&mut accepted).await?;
        accept_tx
            .send(())
            .map_err(|_| "initiator ended early".to_owned())?;
        {
            let mut state = lock_state(&state).await?;
            state.cancel_operation();
            state.observe_publication(Publication::Pending)?;
            state.observe_publication(Publication::Visible)?;
            state.observe_publication(Publication::Acknowledged)?;
        }
        let initiator = tasks
            .observe("initiator")
            .await
            .map_err(|error| format!("initiator join failed: {error}"))?;
        initiator.map_err(str::to_owned)?;
        result_tx
            .send(Outcome::Observed)
            .map_err(|_| "supervisor ended before outcome".to_owned())?;
        let mut checked = checked_rx;
        let refusal = recv(&mut checked).await?;
        if refusal != Err("operation cancellation forbids protected mutation") {
            return Err(format!("wrong cancellation refusal: {refusal:?}"));
        }
        let supervisor = tasks
            .observe("supervisor")
            .await
            .map_err(|error| format!("supervisor join failed: {error}"))?;
        supervisor.map_err(str::to_owned)?;
        Ok::<(), String>(())
    }
    .await;
    let cleanup = tasks.cleanup().await;
    assert!(cleanup.is_ok(), "{cleanup:?}");
    assert!(scenario.is_ok(), "{scenario:?}");
    let state = state.lock().await;
    assert_eq!(state.outcomes, [Outcome::Observed]);
    assert_eq!(state.protected_mutations, 0);
    assert!(state.refusal_closed);
    assert!(!state.participation_allowed);
}

#[derive(Clone, Copy)]
enum PublishResult {
    Acknowledged,
    Failed,
    Uncertain,
}

#[tokio::test]
async fn publication_completion_before_and_after_cancellation_preserves_outcome() {
    for (name, result, cancel_first, expected) in [
        (
            "before-cancel",
            PublishResult::Acknowledged,
            false,
            Publication::Acknowledged,
        ),
        (
            "after-cancel",
            PublishResult::Acknowledged,
            true,
            Publication::Acknowledged,
        ),
        ("failed", PublishResult::Failed, false, Publication::Failed),
        (
            "uncertain",
            PublishResult::Uncertain,
            true,
            Publication::Uncertain,
        ),
    ] {
        let state = std::sync::Arc::new(Mutex::new(SyntheticState::new()));
        state
            .lock()
            .await
            .observe_publication(Publication::Pending)
            .unwrap();
        let (release_tx, release_rx) = oneshot::channel::<PublishResult>();
        let (done_tx, done_rx) = mpsc::unbounded_channel::<Publication>();
        let publisher_state = state.clone();
        let mut tasks = Tasks::default();
        tasks.spawn(name, async move {
            let result = release_rx.await.map_err(|_| "publisher gate dropped")?;
            let publication = match result {
                PublishResult::Acknowledged => Publication::Acknowledged,
                PublishResult::Failed => Publication::Failed,
                PublishResult::Uncertain => Publication::Uncertain,
            };
            let mut state = publisher_state.lock().await;
            if publication == Publication::Acknowledged {
                state.observe_publication(Publication::Visible)?;
            }
            state.observe_publication(publication)?;
            drop(state);
            done_tx
                .send(publication)
                .map_err(|_| "test receiver unavailable")?;
            Ok(())
        });

        let scenario = async {
            if cancel_first {
                state.lock().await.cancel_operation();
            }
            release_tx
                .send(result)
                .map_err(|_| "publisher ended before mock result".to_owned())?;
            let mut done = done_rx;
            let publication = recv(&mut done).await?;
            if publication != expected {
                return Err("mock publisher result differed".into());
            }
            let mut publisher_joined = false;
            if !cancel_first && name == "before-cancel" {
                let joined = tasks
                    .observe(name)
                    .await
                    .map_err(|error| format!("publisher join failed: {error}"))?;
                joined.map_err(str::to_owned)?;
                publisher_joined = true;
                state.lock().await.cancel_operation();
            }
            if !publisher_joined {
                let joined = tasks
                    .observe(name)
                    .await
                    .map_err(|error| format!("publisher join failed: {error}"))?;
                joined.map_err(str::to_owned)?;
            }
            let state = lock_state(&state).await?;
            if state.publication != expected {
                return Err(format!("publication outcome lost: {:?}", state.publication));
            }
            if state.operation_cancelled && state.participation_allowed {
                return Err("cancellation reopened participation".into());
            }
            if state.protected_mutations != 0 {
                return Err("publication result authorized mutation".into());
            }
            Ok::<(), String>(())
        }
        .await;
        let cleanup = tasks.cleanup().await;
        assert!(cleanup.is_ok(), "{name}: {cleanup:?}");
        assert!(scenario.is_ok(), "{name}: {scenario:?}");
    }

    let state = std::sync::Arc::new(Mutex::new(SyntheticState::new()));
    state
        .lock()
        .await
        .observe_publication(Publication::Pending)
        .unwrap();
    let (_release_tx, release_rx) = oneshot::channel::<PublishResult>();
    let mut tasks = Tasks::default();
    tasks.spawn("aborted-publisher", async move {
        let _ = release_rx.await;
        Ok(())
    });
    let scenario = async {
        let termination = tasks
            .abort_and_observe("aborted-publisher")
            .await
            .map_err(|error| error.to_string())?;
        if termination != TaskTermination::Cancelled {
            return Err(format!("publisher was not cancelled: {termination:?}"));
        }
        state
            .lock()
            .await
            .observe_publication(Publication::Uncertain)?;
        let mut state = lock_state(&state).await?;
        if state.publication != Publication::Uncertain || !state.refusal_closed {
            return Err("aborted pending publication did not remain uncertain".into());
        }
        if state.admit_protected_mutation(Owner::Initiator).is_ok() {
            return Err("aborted publication authorized mutation".into());
        }
        Ok::<(), String>(())
    }
    .await;
    let cleanup = tasks.cleanup().await;
    assert!(cleanup.is_ok(), "aborted publisher: {cleanup:?}");
    assert!(scenario.is_ok(), "aborted publisher: {scenario:?}");
}

#[tokio::test]
async fn supervisor_records_publication_after_initiator_task_ends() {
    let state = std::sync::Arc::new(Mutex::new(SyntheticState::new()));
    {
        let mut state = state.lock().await;
        state.observe_publication(Publication::Pending).unwrap();
        state.offer_handoff().unwrap();
    }
    let (offer_tx, mut offer_rx) = mpsc::unbounded_channel::<()>();
    let (accept_tx, accept_rx) = oneshot::channel::<()>();
    let (accepted_tx, accepted_rx) = mpsc::unbounded_channel::<()>();
    let (publication_tx, publication_rx) = oneshot::channel::<Publication>();
    let (observed_tx, observed_rx) = mpsc::unbounded_channel::<Publication>();
    let mut tasks = Tasks::default();

    tasks.spawn("initiator", async move {
        offer_tx.send(()).map_err(|_| "supervisor unavailable")?;
        accept_rx.await.map_err(|_| "handoff refused")?;
        Ok(())
    });
    let supervisor_state = state.clone();
    tasks.spawn("supervisor", async move {
        offer_rx.recv().await.ok_or("offer missing")?;
        supervisor_state.lock().await.accept_handoff()?;
        accepted_tx
            .send(())
            .map_err(|_| "test receiver unavailable")?;
        let publication = publication_rx
            .await
            .map_err(|_| "late publication result missing")?;
        supervisor_state
            .lock()
            .await
            .observe_publication(publication)?;
        observed_tx
            .send(publication)
            .map_err(|_| "test receiver unavailable")?;
        Ok(())
    });

    let scenario = async {
        let mut accepted = accepted_rx;
        recv(&mut accepted).await?;
        accept_tx
            .send(())
            .map_err(|_| "initiator ended before handoff".to_owned())?;
        let initiator = tasks
            .observe("initiator")
            .await
            .map_err(|error| format!("initiator join failed: {error}"))?;
        initiator.map_err(str::to_owned)?;
        {
            let state = lock_state(&state).await?;
            if state.owner != Owner::Supervisor || state.publication != Publication::Pending {
                return Err("supervisor did not retain the pending publication".into());
            }
        }
        publication_tx
            .send(Publication::Visible)
            .map_err(|_| "supervisor ended before publication became visible".to_owned())?;
        let mut observed = observed_rx;
        if recv(&mut observed).await? != Publication::Visible {
            return Err("supervisor did not record late visibility".into());
        }
        let supervisor = tasks
            .observe("supervisor")
            .await
            .map_err(|error| format!("supervisor join failed: {error}"))?;
        supervisor.map_err(str::to_owned)?;
        let mut state = lock_state(&state).await?;
        if state.owner != Owner::Supervisor
            || state.publication != Publication::Visible
            || !state.refusal_closed
        {
            return Err("late visibility was not retained under supervisor ownership".into());
        }
        if state.admit_protected_mutation(Owner::Supervisor).is_ok() {
            return Err("late publication visibility authorized mutation".into());
        }
        Ok::<(), String>(())
    }
    .await;
    let cleanup = tasks.cleanup().await;
    assert!(cleanup.is_ok(), "late publication: {cleanup:?}");
    assert!(scenario.is_ok(), "late publication: {scenario:?}");
    let state = state.lock().await;
    assert_eq!(state.protected_mutations, 0);
    assert!(state.refusal_closed);
}

#[tokio::test]
async fn supervisor_abort_is_observed_and_late_external_result_stays_closed() {
    let state = std::sync::Arc::new(Mutex::new(SyntheticState::new()));
    {
        let mut state = state.lock().await;
        state.begin_work().unwrap();
        state.offer_handoff().unwrap();
    }
    let (release_tx, release_rx) = oneshot::channel::<Outcome>();
    let (observed_tx, observed_rx) = mpsc::unbounded_channel::<Outcome>();
    let (supervisor_started_tx, mut supervisor_started_rx) = mpsc::unbounded_channel::<()>();
    let result_state = state.clone();
    let mut tasks = Tasks::default();

    tasks.spawn("external-result", async move {
        let outcome = release_rx
            .await
            .map_err(|_| "external result gate dropped")?;
        result_state.lock().await.observe_outcome(outcome)?;
        observed_tx
            .send(outcome)
            .map_err(|_| "test receiver unavailable")?;
        Ok(())
    });
    let supervisor_state = state.clone();
    tasks.spawn("supervisor", async move {
        supervisor_state.lock().await.accept_handoff()?;
        supervisor_started_tx
            .send(())
            .map_err(|_| "test receiver unavailable")?;
        std::future::pending::<()>().await;
        Ok(())
    });

    let scenario = async {
        recv(&mut supervisor_started_rx).await?;
        tasks
            .abort_owner_and_observe_loss("supervisor", &state)
            .await
            .map_err(|error| error.to_string())?;
        {
            let state = lock_state(&state).await?;
            if state.owner != Owner::Lost || !state.handoff_accepted {
                return Err("supervisor did not accept responsibility".into());
            }
        }
        release_tx
            .send(Outcome::Unknown)
            .map_err(|_| "external worker ended before result".to_owned())?;
        let mut observed = observed_rx;
        if recv(&mut observed).await? != Outcome::Unknown {
            return Err("late external result not observed".into());
        }
        let worker = tasks
            .observe("external-result")
            .await
            .map_err(|error| format!("external worker join failed: {error}"))?;
        worker.map_err(str::to_owned)?;
        let mut state = lock_state(&state).await?;
        if state.owner != Owner::Lost || state.outcomes != [Outcome::Unknown] {
            return Err("supervisor loss or late result erased state".into());
        }
        if !state.worker_completed || state.effect_known {
            return Err("unknown external effect was not retained as unresolved".into());
        }
        if state.admit_protected_mutation(Owner::Supervisor).is_ok() {
            return Err("late completion reopened participation".into());
        }
        Ok::<(), String>(())
    }
    .await;
    let cleanup = tasks.cleanup().await;
    assert!(cleanup.is_ok(), "{cleanup:?}");
    assert!(scenario.is_ok(), "{scenario:?}");
}

#[tokio::test]
async fn successful_application_and_cleanup_do_not_reopen_participation() {
    let state = std::sync::Arc::new(Mutex::new(SyntheticState::new()));
    let (apply_tx, apply_rx) = oneshot::channel::<()>();
    let (done_tx, done_rx) = mpsc::unbounded_channel::<()>();
    let (_cleanup_release_tx, cleanup_release_rx) = oneshot::channel::<()>();
    let task_state = state.clone();
    let mut tasks = Tasks::default();

    tasks.spawn("application", async move {
        apply_rx.await.map_err(|_| "application gate dropped")?;
        let mut state = task_state.lock().await;
        state.observe_publication(Publication::Pending)?;
        state.observe_publication(Publication::Visible)?;
        state.observe_publication(Publication::Acknowledged)?;
        state.begin_work()?;
        state.observe_outcome(Outcome::Observed)?;
        state
            .admit_protected_mutation(Owner::Initiator)
            .map_err(|_| "application refused")?;
        done_tx.send(()).map_err(|_| "test receiver unavailable")?;
        Ok(())
    });
    tasks.spawn("cleanup-watcher", async move {
        cleanup_release_rx
            .await
            .map_err(|_| "cleanup watcher released")?;
        Ok(())
    });

    let scenario = async {
        apply_tx
            .send(())
            .map_err(|_| "application ended before release".to_owned())?;
        let mut done = done_rx;
        recv(&mut done).await?;
        let result = tasks
            .observe("application")
            .await
            .map_err(|error| format!("application join failed: {error}"))?;
        result.map_err(str::to_owned)?;
        {
            let mut state = lock_state(&state).await?;
            state
                .observe_application_task_completion()
                .map_err(str::to_owned)?;
            if state.owner != Owner::Initiator || state.operation_cancelled {
                return Err("task completion incorrectly changed owner or cancellation".into());
            }
        }
        Ok::<(), String>(())
    }
    .await;
    let cleanup = tasks.cleanup().await;
    assert!(cleanup.is_ok(), "{cleanup:?}");
    assert!(scenario.is_ok(), "{scenario:?}");
    {
        let mut state = state.lock().await;
        state.observe_cleanup_completion().unwrap();
        assert_eq!(state.owner, Owner::Initiator);
        assert!(state.application_task_completed);
        assert!(state.cleanup_observed);
        assert!(!state.operation_cancelled);
        assert!(!state.operation_retired);
        state.retire_operation(Owner::Initiator).unwrap();
        assert!(state.operation_retired);
        assert_eq!(state.protected_mutations, 1);
        assert_eq!(
            require_completed_authority_refusal(&mut state, Owner::Initiator),
            Ok(())
        );
        assert_eq!(state.protected_mutations, 1);

        state
            .record_late_outcome(Owner::Initiator, Outcome::Unknown)
            .unwrap();
        assert_eq!(
            state.observe_publication(Publication::Uncertain),
            Ok(()),
            "late uncertainty may be recorded after retirement"
        );
        assert_eq!(
            state.observe_publication(Publication::Acknowledged),
            Err("publication attempt is uncertain and terminal")
        );
        assert_eq!(
            require_completed_authority_refusal(&mut state, Owner::Initiator),
            Ok(()),
            "late outcomes cannot restore retired authority"
        );
        assert_eq!(state.protected_mutations, 1);
        assert_eq!(state.outcomes, [Outcome::Observed, Outcome::Unknown]);
        assert_eq!(state.effect_known, true);
        assert!(state.validate_refusal_closed().is_ok());
    }

    let mut live = SyntheticState::new();
    live.observe_publication(Publication::Pending).unwrap();
    live.observe_publication(Publication::Visible).unwrap();
    live.observe_publication(Publication::Acknowledged).unwrap();
    live.begin_work().unwrap();
    live.observe_outcome(Outcome::Observed).unwrap();
    assert!(!live.operation_retired);
    assert_eq!(live.admit_protected_mutation(Owner::Initiator), Ok(()));
    assert_eq!(live.admit_protected_mutation(Owner::Initiator), Ok(()));
    assert_eq!(
        live.protected_mutations, 2,
        "live operation may perform multiple mutations; retirement is the boundary"
    );
}

#[tokio::test]
async fn omitted_retirement_sensitivity_detects_post_completion_mutation() {
    let mut state = SyntheticState::new();
    state.observe_publication(Publication::Pending).unwrap();
    state.observe_publication(Publication::Visible).unwrap();
    state
        .observe_publication(Publication::Acknowledged)
        .unwrap();
    state.begin_work().unwrap();
    state.observe_outcome(Outcome::Observed).unwrap();
    assert_eq!(state.admit_protected_mutation(Owner::Initiator), Ok(()));
    state.observe_application_task_completion().unwrap();
    state.observe_cleanup_completion().unwrap();

    assert!(state.application_task_completed);
    assert!(state.cleanup_observed);
    assert!(!state.operation_cancelled);
    assert!(
        !state.operation_retired,
        "defective trace deliberately omits retirement"
    );
    assert!(state.validate_refusal_closed().is_ok());
    assert_eq!(
        require_completed_authority_refusal(&mut state, Owner::Initiator),
        Err("retirement check detected mutation admitted after completion"),
        "valid completed prefix must detect the omitted retirement transition"
    );
    assert_eq!(state.protected_mutations, 2);
}

#[tokio::test]
async fn unknown_effect_blocks_mutation_but_known_disposition_allows_it() {
    let unknown = std::sync::Arc::new(Mutex::new(SyntheticState::new()));
    {
        let mut state = unknown.lock().await;
        state.observe_publication(Publication::Pending).unwrap();
        state.observe_publication(Publication::Visible).unwrap();
        state
            .observe_publication(Publication::Acknowledged)
            .unwrap();
        state.begin_work().unwrap();
        state.observe_outcome(Outcome::Unknown).unwrap();
        assert!(state.worker_completed, "worker completion must be distinct");
        assert!(!state.work_pending);
        assert!(!state.effect_known, "Unknown must remain unresolved");
        assert_eq!(
            state.admit_protected_mutation(Owner::Initiator),
            Err("protected mutation blocked by unresolved external effect"),
            "valid publication/work prefix must reject mutation due to Unknown effect"
        );
        assert_eq!(
            state.observe_outcome(Outcome::Observed),
            Err("worker completion was already observed or not admitted"),
            "duplicate known outcome must not resolve an Unknown effect"
        );
        assert!(!state.effect_known);
    }

    let known = std::sync::Arc::new(Mutex::new(SyntheticState::new()));
    {
        let mut state = known.lock().await;
        state.observe_publication(Publication::Pending).unwrap();
        state.observe_publication(Publication::Visible).unwrap();
        state
            .observe_publication(Publication::Acknowledged)
            .unwrap();
        state.begin_work().unwrap();
        state.observe_outcome(Outcome::Observed).unwrap();
        assert!(state.worker_completed);
        assert!(state.effect_known);
        assert_eq!(state.admit_protected_mutation(Owner::Initiator), Ok(()));
        assert_eq!(state.protected_mutations, 1);
    }
}

#[tokio::test]
async fn failed_and_uncertain_publication_attempts_cannot_become_acknowledged() {
    let mut failed = SyntheticState::new();
    assert_eq!(
        failed.observe_publication(Publication::Pending),
        Ok(()),
        "pending publication is a valid prefix"
    );
    assert_eq!(failed.observe_publication(Publication::Failed), Ok(()));
    assert_eq!(failed.publication, Publication::Failed);
    assert_eq!(
        failed.observe_publication(Publication::Acknowledged),
        Err("publication attempt failed and is terminal"),
        "Failed -> Acknowledged must be rejected"
    );
    assert_eq!(failed.publication, Publication::Failed);
    assert_eq!(
        failed.admit_protected_mutation(Owner::Initiator),
        Err("protected mutation requires acknowledged publication")
    );

    let mut uncertain = SyntheticState::new();
    assert_eq!(uncertain.observe_publication(Publication::Pending), Ok(()));
    assert_eq!(
        uncertain.observe_publication(Publication::Uncertain),
        Ok(()),
        "pending -> uncertain is a valid prefix"
    );
    assert_eq!(uncertain.publication, Publication::Uncertain);
    assert_eq!(
        uncertain.observe_publication(Publication::Failed),
        Err("publication attempt is uncertain and terminal"),
        "Uncertain -> Failed must be rejected"
    );
    assert_eq!(
        uncertain.observe_publication(Publication::Acknowledged),
        Err("publication attempt is uncertain and terminal"),
        "Uncertain -> Acknowledged must be rejected"
    );
    assert_eq!(uncertain.publication, Publication::Uncertain);
    assert_eq!(
        uncertain.admit_protected_mutation(Owner::Initiator),
        Err("protected mutation requires acknowledged publication")
    );
}

#[tokio::test]
async fn missing_owner_loss_transition_after_observed_task_abort_is_rejected() {
    let state = std::sync::Arc::new(Mutex::new(SyntheticState::new()));
    {
        let mut state = state.lock().await;
        state.observe_publication(Publication::Pending).unwrap();
        state.observe_publication(Publication::Visible).unwrap();
        state
            .observe_publication(Publication::Acknowledged)
            .unwrap();
        state.offer_handoff().unwrap();
    }
    let (started_tx, mut started_rx) = mpsc::unbounded_channel::<()>();
    let (_gate_tx, gate_rx) = oneshot::channel::<()>();
    let supervisor_state = state.clone();
    let mut tasks = Tasks::default();
    tasks.spawn("supervisor", async move {
        supervisor_state.lock().await.accept_handoff()?;
        started_tx
            .send(())
            .map_err(|_| "test receiver unavailable")?;
        gate_rx.await.map_err(|_| "supervisor gate dropped")?;
        Ok(())
    });

    let scenario = async {
        recv(&mut started_rx).await?;
        let termination = tasks
            .abort_and_observe("supervisor")
            .await
            .map_err(|error| error.to_string())?;
        if termination != TaskTermination::Cancelled {
            return Err(format!("expected observed abort, got {termination:?}"));
        }
        {
            let mut state = lock_state(&state).await?;
            if state.owner != Owner::Supervisor || !state.handoff_accepted {
                return Err("supervisor acceptance prefix was not established".into());
            }
            state
                .observe_owner_task_termination()
                .map_err(str::to_owned)?;
            assert_eq!(
                state.admit_protected_mutation(Owner::Supervisor),
                Err("ownership loss transition is missing after task termination"),
                "faulted prefix must detect omitted ownership-loss transition"
            );
            state.lose_owner().map_err(str::to_owned)?;
            assert_eq!(state.owner, Owner::Lost);
            assert!(state.validate_refusal_closed().is_ok());
        }
        Ok::<(), String>(())
    }
    .await;
    let cleanup = tasks.cleanup().await;
    assert!(
        cleanup.is_ok(),
        "missed-owner-loss sensitivity: {cleanup:?}"
    );
    assert!(
        scenario.is_ok(),
        "missed-owner-loss sensitivity: {scenario:?}"
    );
}

#[tokio::test]
async fn sensitivity_controls_reject_unauthorized_mutation_handoff_and_reopen() {
    let state = std::sync::Arc::new(Mutex::new(SyntheticState::new()));
    {
        let state = state.lock().await;
        assert!(state.refusal_closed);
        assert_eq!(
            state.owner,
            Owner::Initiator,
            "valid initial prefix must be accepted"
        );
    }

    let mut unauthorized = state.lock().await;
    assert_eq!(
        unauthorized.admit_protected_mutation(Owner::Supervisor),
        Err("mutation actor does not own refusal responsibility")
    );
    assert_eq!(
        unauthorized.accept_handoff(),
        Err("supervisor ownership transferred before acceptance")
    );
    assert_eq!(
        unauthorized.reopen(),
        Err("no modeled transition may reopen participation")
    );
    unauthorized.participation_allowed = true;
    assert_eq!(
        unauthorized.validate_refusal_closed(),
        Err("refusal latch reopened"),
        "faulted unauthorized reopening must be detected"
    );
    unauthorized.participation_allowed = false;
    assert!(unauthorized.refusal_closed);
    assert!(!unauthorized.participation_allowed);
}
