#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestedMode {
    Persistent,
    InMemory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpenOutcome {
    Succeeded,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OpenObservation {
    initialization_id: u64,
    sequence: u8,
    outcome: OpenOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Backend {
    Persistent,
    InMemory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RefusalReason {
    PersistentOpenFailed,
    OtherSetupFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InitializationOutcome {
    Published {
        sequence: u8,
        backend: Backend,
    },
    Refused(RefusalReason),
    Pending,
    TimedOut,
    Panicked,
    MissingResponse,
    SetupFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkerOutcome {
    NotStarted,
    Terminated,
    Running,
    CancellationRequested,
    WaiterDropped,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InitializationTrace {
    initialization_id: u64,
    requested_mode: RequestedMode,
    open: Option<OpenObservation>,
    outcome: InitializationOutcome,
    worker: WorkerOutcome,
    submitted_work: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Classification {
    PersistentReady,
    ExplicitInMemoryReady,
    PersistentOpenRefused,
    ContractViolation,
    Inconclusive,
}

fn classify(trace: InitializationTrace) -> Classification {
    match (trace.requested_mode, trace.outcome) {
        (
            RequestedMode::Persistent,
            InitializationOutcome::Published {
                sequence,
                backend: Backend::Persistent,
            },
        ) => match trace.open {
            Some(OpenObservation {
                initialization_id,
                sequence: open_sequence,
                outcome: OpenOutcome::Succeeded,
            }) if initialization_id == trace.initialization_id && open_sequence < sequence => {
                Classification::PersistentReady
            }
            _ => Classification::ContractViolation,
        },
        (
            RequestedMode::Persistent,
            InitializationOutcome::Published {
                backend: Backend::InMemory,
                ..
            },
        ) => Classification::ContractViolation,
        (
            RequestedMode::Persistent,
            InitializationOutcome::Refused(RefusalReason::PersistentOpenFailed),
        ) => {
            let matching_failed_open = matches!(
                trace.open,
                Some(OpenObservation {
                    initialization_id,
                    outcome: OpenOutcome::Failed,
                    ..
                }) if initialization_id == trace.initialization_id
            );
            let worker_accounted_for = matches!(
                trace.worker,
                WorkerOutcome::NotStarted | WorkerOutcome::Terminated
            );
            if matching_failed_open && worker_accounted_for && trace.submitted_work == 0 {
                Classification::PersistentOpenRefused
            } else if matching_failed_open && !worker_accounted_for {
                Classification::Inconclusive
            } else {
                Classification::ContractViolation
            }
        }
        (
            RequestedMode::InMemory,
            InitializationOutcome::Published {
                backend: Backend::InMemory,
                ..
            },
        ) if trace.open.is_none() => Classification::ExplicitInMemoryReady,
        (_, InitializationOutcome::Pending)
        | (_, InitializationOutcome::TimedOut)
        | (_, InitializationOutcome::Panicked)
        | (_, InitializationOutcome::MissingResponse)
        | (_, InitializationOutcome::SetupFailed)
        | (_, InitializationOutcome::Refused(RefusalReason::OtherSetupFailure)) => {
            Classification::Inconclusive
        }
        _ => Classification::ContractViolation,
    }
}

fn persistent_success(initialization_id: u64) -> InitializationTrace {
    InitializationTrace {
        initialization_id,
        requested_mode: RequestedMode::Persistent,
        open: Some(OpenObservation {
            initialization_id,
            sequence: 1,
            outcome: OpenOutcome::Succeeded,
        }),
        outcome: InitializationOutcome::Published {
            sequence: 2,
            backend: Backend::Persistent,
        },
        worker: WorkerOutcome::Running,
        submitted_work: 0,
    }
}

fn open_failure_refusal(initialization_id: u64, worker: WorkerOutcome) -> InitializationTrace {
    InitializationTrace {
        initialization_id,
        requested_mode: RequestedMode::Persistent,
        open: Some(OpenObservation {
            initialization_id,
            sequence: 1,
            outcome: OpenOutcome::Failed,
        }),
        outcome: InitializationOutcome::Refused(RefusalReason::PersistentOpenFailed),
        worker,
        submitted_work: 0,
    }
}

#[test]
fn matching_persistent_open_precedes_same_instance_availability() {
    let trace = persistent_success(7);
    assert_eq!(classify(trace), Classification::PersistentReady);
}

#[test]
fn open_failure_is_identifiable_early_refusal_without_submission() {
    let trace = open_failure_refusal(8, WorkerOutcome::NotStarted);
    assert_eq!(trace.submitted_work, 0);
    assert_eq!(classify(trace), Classification::PersistentOpenRefused);
}

#[test]
fn explicitly_selected_in_memory_is_a_separate_positive_case() {
    let trace = InitializationTrace {
        initialization_id: 9,
        requested_mode: RequestedMode::InMemory,
        open: None,
        outcome: InitializationOutcome::Published {
            sequence: 1,
            backend: Backend::InMemory,
        },
        worker: WorkerOutcome::Running,
        submitted_work: 0,
    };
    assert_eq!(classify(trace), Classification::ExplicitInMemoryReady);
}

#[test]
fn fallback_after_requested_persistent_open_failure_is_rejected() {
    let trace = InitializationTrace {
        outcome: InitializationOutcome::Published {
            sequence: 2,
            backend: Backend::InMemory,
        },
        ..open_failure_refusal(10, WorkerOutcome::Running)
    };
    assert_eq!(classify(trace), Classification::ContractViolation);
}

#[test]
fn publication_before_matching_open_success_is_rejected() {
    let trace = InitializationTrace {
        outcome: InitializationOutcome::Published {
            sequence: 1,
            backend: Backend::Persistent,
        },
        open: Some(OpenObservation {
            initialization_id: 11,
            sequence: 2,
            outcome: OpenOutcome::Succeeded,
        }),
        ..persistent_success(11)
    };
    assert_eq!(classify(trace), Classification::ContractViolation);
}

#[test]
fn another_initializations_open_cannot_satisfy_this_instance() {
    let trace = InitializationTrace {
        open: Some(OpenObservation {
            initialization_id: 12,
            sequence: 1,
            outcome: OpenOutcome::Succeeded,
        }),
        ..persistent_success(13)
    };
    assert_eq!(classify(trace), Classification::ContractViolation);
}

#[test]
fn another_initializations_failed_open_cannot_satisfy_this_refusal() {
    let trace = InitializationTrace {
        open: Some(OpenObservation {
            initialization_id: 17,
            sequence: 1,
            outcome: OpenOutcome::Failed,
        }),
        ..open_failure_refusal(18, WorkerOutcome::NotStarted)
    };
    assert_eq!(classify(trace), Classification::ContractViolation);
}

#[test]
fn pending_timeout_panic_missing_response_and_setup_failure_are_not_refusal() {
    for outcome in [
        InitializationOutcome::Pending,
        InitializationOutcome::TimedOut,
        InitializationOutcome::Panicked,
        InitializationOutcome::MissingResponse,
        InitializationOutcome::SetupFailed,
        InitializationOutcome::Refused(RefusalReason::OtherSetupFailure),
    ] {
        let trace = InitializationTrace {
            initialization_id: 14,
            requested_mode: RequestedMode::Persistent,
            open: None,
            outcome,
            worker: WorkerOutcome::Unknown,
            submitted_work: 0,
        };
        assert_eq!(
            classify(trace),
            Classification::Inconclusive,
            "{outcome:?} must not be classified as successful open refusal"
        );
    }
}

#[test]
fn started_worker_must_terminate_or_refusal_remains_unresolved() {
    assert_eq!(
        classify(open_failure_refusal(15, WorkerOutcome::Terminated)),
        Classification::PersistentOpenRefused
    );
    for worker in [
        WorkerOutcome::Running,
        WorkerOutcome::CancellationRequested,
        WorkerOutcome::WaiterDropped,
        WorkerOutcome::Unknown,
    ] {
        assert_eq!(
            classify(open_failure_refusal(15, worker)),
            Classification::Inconclusive,
            "{worker:?} does not establish worker termination"
        );
    }
}

#[test]
fn refusal_with_submitted_work_is_not_an_early_refusal() {
    let trace = InitializationTrace {
        submitted_work: 1,
        ..open_failure_refusal(16, WorkerOutcome::NotStarted)
    };
    assert_eq!(classify(trace), Classification::ContractViolation);
}
