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
enum InitSignal {
    Pending,
    TimedOut,
    Panicked,
    MissingResponse,
    SetupFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkEvent {
    Attempted { work_id: u64 },
    Rejected { work_id: u64 },
    Admitted { work_id: u64 },
    Executed { work_id: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EventKind {
    OpenCompleted(OpenOutcome),
    ServicePublished(Backend),
    Refused(RefusalReason),
    Signal(InitSignal),
    WorkerStarted { worker_id: u64 },
    WorkerStatusObserved {
        worker_id: u64,
        status: WorkerStatus,
    },
    WorkerTerminated { worker_id: u64 },
    Work(WorkEvent),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkerStatus {
    Running,
    Unknown,
    CancellationRequested,
    WaiterDropped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Event {
    initialization_id: u64,
    sequence: u8,
    kind: EventKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InitializationTrace<'a> {
    initialization_id: u64,
    requested_mode: RequestedMode,
    events: &'a [Event],
    event_history_complete: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Classification {
    PersistentReady,
    ExplicitInMemoryReady,
    PersistentOpenRefused,
    ContractViolation,
    Inconclusive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkerTermination {
    NotStarted,
    Terminated,
    Unresolved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkEvidence {
    Consistent,
    Unresolved,
    Violation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Assessment {
    classification: Classification,
    worker_termination: WorkerTermination,
}

fn classify(trace: InitializationTrace<'_>) -> Assessment {
    let worker_termination = worker_termination(trace);
    let mut matching_events: Vec<_> = trace
        .events
        .iter()
        .filter(|event| event.initialization_id == trace.initialization_id)
        .collect();
    matching_events.sort_by_key(|event| event.sequence);
    if matching_events
        .windows(2)
        .any(|pair| pair[0].sequence == pair[1].sequence)
    {
        return Assessment {
            classification: Classification::ContractViolation,
            worker_termination: WorkerTermination::Unresolved,
        };
    }

    let publication = matching_events.iter().find_map(|event| match event.kind {
        EventKind::ServicePublished(backend) => Some((event.sequence, backend)),
        _ => None,
    });
    let refusal = matching_events.iter().find_map(|event| match event.kind {
        EventKind::Refused(reason) => Some((event.sequence, reason)),
        _ => None,
    });
    let open = matching_events.iter().find_map(|event| match event.kind {
        EventKind::OpenCompleted(outcome) => Some((event.sequence, outcome)),
        _ => None,
    });

    let has_executable_work = matching_events.iter().any(|event| {
        matches!(
            event.kind,
            EventKind::Work(WorkEvent::Admitted { .. } | WorkEvent::Executed { .. })
        )
    });
    let work_evidence = work_evidence(&matching_events);

    let classification = match trace.requested_mode {
        RequestedMode::Persistent => {
            if has_executable_work && refusal.is_some() {
                Classification::ContractViolation
            } else if let Some((published_at, backend)) = publication {
                match (backend, open) {
                    (
                        Backend::Persistent,
                        Some((opened_at, OpenOutcome::Succeeded)),
                    ) if opened_at < published_at && refusal.is_none() => {
                        Classification::PersistentReady
                    }
                    (Backend::InMemory, _) => Classification::ContractViolation,
                    _ => Classification::ContractViolation,
                }
            } else if let Some((refused_at, RefusalReason::PersistentOpenFailed)) = refusal {
                let failed_before_refusal = matches!(
                    open,
                    Some((opened_at, OpenOutcome::Failed)) if opened_at < refused_at
                );
                let publication_precedes_refusal =
                    publication.is_some_and(|(published_at, _)| published_at < refused_at);
                let publication_follows_refusal =
                    publication.is_some_and(|(published_at, _)| published_at > refused_at);
                let only_rejected_attempts =
                    !has_executable_work && work_evidence == WorkEvidence::Consistent;
                let conflicting_signal = matching_events.iter().any(|event| {
                    matches!(
                        event.kind,
                        EventKind::Signal(
                            InitSignal::Pending
                                | InitSignal::TimedOut
                                | InitSignal::Panicked
                                | InitSignal::MissingResponse
                                | InitSignal::SetupFailed
                        )
                    )
                });

                if work_evidence == WorkEvidence::Violation
                    || publication_precedes_refusal
                    || publication_follows_refusal
                    || open.is_some_and(|(opened_at, _)| opened_at > refused_at)
                {
                    Classification::ContractViolation
                } else if work_evidence == WorkEvidence::Unresolved {
                    Classification::Inconclusive
                } else if conflicting_signal {
                    Classification::Inconclusive
                } else if !trace.event_history_complete {
                    Classification::Inconclusive
                } else if failed_before_refusal
                    && only_rejected_attempts
                {
                    if worker_termination == WorkerTermination::Unresolved {
                        Classification::Inconclusive
                    } else {
                        Classification::PersistentOpenRefused
                    }
                } else {
                    Classification::ContractViolation
                }
            } else if refusal.is_some_and(|(_, reason)| {
                reason == RefusalReason::OtherSetupFailure
            }) || matching_events.iter().any(|event| {
                matches!(
                    event.kind,
                    EventKind::Signal(
                        InitSignal::Pending
                            | InitSignal::TimedOut
                            | InitSignal::Panicked
                            | InitSignal::MissingResponse
                            | InitSignal::SetupFailed
                    )
                )
            }) || refusal.is_none()
            {
                Classification::Inconclusive
            } else {
                Classification::ContractViolation
            }
        }
        RequestedMode::InMemory => match publication {
            Some((_, Backend::InMemory)) if open.is_none() && refusal.is_none() => {
                Classification::ExplicitInMemoryReady
            }
            Some((_, Backend::Persistent)) => Classification::ContractViolation,
            Some((_, Backend::InMemory)) => Classification::ContractViolation,
            None => Classification::Inconclusive,
        },
    };

    Assessment {
        classification,
        worker_termination,
    }
}

fn worker_termination(trace: InitializationTrace<'_>) -> WorkerTermination {
    let mut matching_events: Vec<_> = trace
        .events
        .iter()
        .filter(|event| event.initialization_id == trace.initialization_id)
        .collect();
    matching_events.sort_by_key(|event| event.sequence);
    if matching_events
        .windows(2)
        .any(|pair| pair[0].sequence == pair[1].sequence)
    {
        return WorkerTermination::Unresolved;
    }
    let starts: Vec<_> = matching_events
        .iter()
        .filter_map(|event| match event.kind {
            EventKind::WorkerStarted { worker_id } => Some((worker_id, event.sequence)),
            _ => None,
        })
        .collect();
    if starts.is_empty() {
        return if trace.event_history_complete {
            WorkerTermination::NotStarted
        } else {
            WorkerTermination::Unresolved
        };
    }

    let all_started_workers_terminated = starts.iter().all(|(worker_id, started_at)| {
        matching_events.iter().any(|event| {
            event.sequence > *started_at
                && matches!(
                    event.kind,
                    EventKind::WorkerTerminated {
                        worker_id: terminated_id
                    } if terminated_id == *worker_id
                )
        })
    });
    if all_started_workers_terminated {
        WorkerTermination::Terminated
    } else {
        WorkerTermination::Unresolved
    }
}

fn work_evidence(events: &[&Event]) -> WorkEvidence {
    let attempts: Vec<_> = events
        .iter()
        .filter_map(|event| match event.kind {
            EventKind::Work(WorkEvent::Attempted { work_id }) => {
                Some((work_id, event.sequence))
            }
            _ => None,
        })
        .collect();
    if attempts
        .iter()
        .enumerate()
        .any(|(index, (work_id, _))| attempts[..index].iter().any(|(prior, _)| prior == work_id))
    {
        return WorkEvidence::Violation;
    }

    let mut unresolved_attempt = false;
    for (work_id, attempted_at) in &attempts {
        let outcomes: Vec<_> = events
            .iter()
            .filter(|event| {
                event.sequence > *attempted_at
                    && matches!(
                        event.kind,
                        EventKind::Work(
                            WorkEvent::Rejected { work_id: outcome_id }
                                | WorkEvent::Admitted { work_id: outcome_id }
                                | WorkEvent::Executed { work_id: outcome_id }
                        ) if outcome_id == *work_id
                    )
            })
            .collect();
        if outcomes.len() > 1 {
            return WorkEvidence::Violation;
        }
        unresolved_attempt |= outcomes.is_empty();
    }

    let orphan_outcome = events.iter().any(|event| match event.kind {
        EventKind::Work(
            WorkEvent::Rejected { work_id }
            | WorkEvent::Admitted { work_id }
            | WorkEvent::Executed { work_id },
        ) => !attempts.iter().any(|(attempt_id, attempted_at)| {
            *attempt_id == work_id && *attempted_at < event.sequence
        }),
        _ => false,
    });
    if orphan_outcome {
        WorkEvidence::Violation
    } else if unresolved_attempt {
        WorkEvidence::Unresolved
    } else {
        WorkEvidence::Consistent
    }
}

const fn event(initialization_id: u64, sequence: u8, kind: EventKind) -> Event {
    Event {
        initialization_id,
        sequence,
        kind,
    }
}

fn assessment(
    trace: InitializationTrace<'_>,
    classification: Classification,
    worker_termination: WorkerTermination,
) {
    assert_eq!(
        classify(trace),
        Assessment {
            classification,
            worker_termination,
        }
    );
}

#[test]
fn matching_persistent_open_precedes_same_instance_availability() {
    const EVENTS: &[Event] = &[
        event(7, 1, EventKind::OpenCompleted(OpenOutcome::Succeeded)),
        event(7, 2, EventKind::ServicePublished(Backend::Persistent)),
    ];
    assessment(
        InitializationTrace {
            initialization_id: 7,
            requested_mode: RequestedMode::Persistent,
            events: EVENTS,
            event_history_complete: true,
        },
        Classification::PersistentReady,
        WorkerTermination::NotStarted,
    );
}

#[test]
fn failed_open_then_refusal_without_worker_or_submission_is_accepted() {
    const EVENTS: &[Event] = &[
        event(8, 1, EventKind::OpenCompleted(OpenOutcome::Failed)),
        event(
            8,
            2,
            EventKind::Refused(RefusalReason::PersistentOpenFailed),
        ),
    ];
    assessment(
        InitializationTrace {
            initialization_id: 8,
            requested_mode: RequestedMode::Persistent,
            events: EVENTS,
            event_history_complete: true,
        },
        Classification::PersistentOpenRefused,
        WorkerTermination::NotStarted,
    );
}

#[test]
fn explicitly_selected_in_memory_is_separate_positive_case() {
    const EVENTS: &[Event] = &[event(
        9,
        1,
        EventKind::ServicePublished(Backend::InMemory),
    )];
    assessment(
        InitializationTrace {
            initialization_id: 9,
            requested_mode: RequestedMode::InMemory,
            events: EVENTS,
            event_history_complete: true,
        },
        Classification::ExplicitInMemoryReady,
        WorkerTermination::NotStarted,
    );
}

#[test]
fn requested_persistence_fallback_after_failed_open_is_rejected() {
    const EVENTS: &[Event] = &[
        event(10, 1, EventKind::OpenCompleted(OpenOutcome::Failed)),
        event(10, 2, EventKind::ServicePublished(Backend::InMemory)),
    ];
    assessment(
        InitializationTrace {
            initialization_id: 10,
            requested_mode: RequestedMode::Persistent,
            events: EVENTS,
            event_history_complete: true,
        },
        Classification::ContractViolation,
        WorkerTermination::NotStarted,
    );
}

#[test]
fn publication_before_open_success_is_rejected() {
    const EVENTS: &[Event] = &[
        event(11, 1, EventKind::ServicePublished(Backend::Persistent)),
        event(11, 2, EventKind::OpenCompleted(OpenOutcome::Succeeded)),
    ];
    assessment(
        InitializationTrace {
            initialization_id: 11,
            requested_mode: RequestedMode::Persistent,
            events: EVENTS,
            event_history_complete: true,
        },
        Classification::ContractViolation,
        WorkerTermination::NotStarted,
    );
}

#[test]
fn unrelated_successful_open_does_not_authorize_publication() {
    const EVENTS: &[Event] = &[
        event(12, 1, EventKind::OpenCompleted(OpenOutcome::Succeeded)),
        event(13, 2, EventKind::ServicePublished(Backend::Persistent)),
    ];
    assessment(
        InitializationTrace {
            initialization_id: 13,
            requested_mode: RequestedMode::Persistent,
            events: EVENTS,
            event_history_complete: true,
        },
        Classification::ContractViolation,
        WorkerTermination::NotStarted,
    );
}

#[test]
fn refusal_before_matching_failed_open_is_rejected() {
    const EVENTS: &[Event] = &[
        event(
            14,
            1,
            EventKind::Refused(RefusalReason::PersistentOpenFailed),
        ),
        event(14, 2, EventKind::OpenCompleted(OpenOutcome::Failed)),
    ];
    assessment(
        InitializationTrace {
            initialization_id: 14,
            requested_mode: RequestedMode::Persistent,
            events: EVENTS,
            event_history_complete: true,
        },
        Classification::ContractViolation,
        WorkerTermination::NotStarted,
    );
}

#[test]
fn publication_then_refusal_is_rejected() {
    const EVENTS: &[Event] = &[
        event(15, 1, EventKind::OpenCompleted(OpenOutcome::Failed)),
        event(15, 2, EventKind::ServicePublished(Backend::Persistent)),
        event(
            15,
            3,
            EventKind::Refused(RefusalReason::PersistentOpenFailed),
        ),
    ];
    assessment(
        InitializationTrace {
            initialization_id: 15,
            requested_mode: RequestedMode::Persistent,
            events: EVENTS,
            event_history_complete: true,
        },
        Classification::ContractViolation,
        WorkerTermination::NotStarted,
    );
}

#[test]
fn unrelated_open_or_refusal_cannot_satisfy_this_initialization() {
    const OPEN_EVENTS: &[Event] = &[
        event(16, 1, EventKind::OpenCompleted(OpenOutcome::Failed)),
        event(
            17,
            2,
            EventKind::Refused(RefusalReason::PersistentOpenFailed),
        ),
    ];
    assessment(
        InitializationTrace {
            initialization_id: 17,
            requested_mode: RequestedMode::Persistent,
            events: OPEN_EVENTS,
            event_history_complete: true,
        },
        Classification::ContractViolation,
        WorkerTermination::NotStarted,
    );

    const REFUSAL_EVENTS: &[Event] = &[
        event(18, 1, EventKind::OpenCompleted(OpenOutcome::Failed)),
        event(
            18,
            2,
            EventKind::Refused(RefusalReason::PersistentOpenFailed),
        ),
        event(
            19,
            3,
            EventKind::Refused(RefusalReason::PersistentOpenFailed),
        ),
    ];
    assessment(
        InitializationTrace {
            initialization_id: 20,
            requested_mode: RequestedMode::Persistent,
            events: REFUSAL_EVENTS,
            event_history_complete: true,
        },
        Classification::Inconclusive,
        WorkerTermination::NotStarted,
    );
}

#[test]
fn unrelated_worker_termination_does_not_terminate_relevant_worker() {
    const EVENTS: &[Event] = &[
        event(20, 1, EventKind::WorkerStarted { worker_id: 200 }),
        event(20, 2, EventKind::OpenCompleted(OpenOutcome::Failed)),
        event(
            20,
            3,
            EventKind::Refused(RefusalReason::PersistentOpenFailed),
        ),
        event(20, 4, EventKind::WorkerTerminated { worker_id: 201 }),
        event(99, 5, EventKind::WorkerTerminated { worker_id: 200 }),
    ];
    assessment(
        InitializationTrace {
            initialization_id: 20,
            requested_mode: RequestedMode::Persistent,
            events: EVENTS,
            event_history_complete: true,
        },
        Classification::Inconclusive,
        WorkerTermination::Unresolved,
    );
}

#[test]
fn matching_worker_termination_establishes_termination() {
    const EVENTS: &[Event] = &[
        event(21, 1, EventKind::WorkerStarted { worker_id: 210 }),
        event(21, 2, EventKind::OpenCompleted(OpenOutcome::Failed)),
        event(
            21,
            3,
            EventKind::Refused(RefusalReason::PersistentOpenFailed),
        ),
        event(21, 4, EventKind::WorkerTerminated { worker_id: 210 }),
    ];
    assessment(
        InitializationTrace {
            initialization_id: 21,
            requested_mode: RequestedMode::Persistent,
            events: EVENTS,
            event_history_complete: true,
        },
        Classification::PersistentOpenRefused,
        WorkerTermination::Terminated,
    );
}

#[test]
fn running_worker_and_cancellation_request_remain_unresolved() {
    for (initialization_id, worker_id, status) in [
        (22, 220, WorkerStatus::Running),
        (23, 230, WorkerStatus::Unknown),
        (24, 240, WorkerStatus::CancellationRequested),
        (29, 290, WorkerStatus::WaiterDropped),
    ] {
        let events = [
            event(initialization_id, 1, EventKind::WorkerStarted { worker_id }),
            event(
                initialization_id,
                2,
                EventKind::OpenCompleted(OpenOutcome::Failed),
            ),
            event(
                initialization_id,
                3,
                EventKind::Refused(RefusalReason::PersistentOpenFailed),
            ),
            event(
                initialization_id,
                4,
                EventKind::WorkerStatusObserved { worker_id, status },
            ),
        ];
        assessment(
            InitializationTrace {
                initialization_id,
                requested_mode: RequestedMode::Persistent,
                events: &events,
                event_history_complete: true,
            },
            Classification::Inconclusive,
            WorkerTermination::Unresolved,
        );
    }
}

#[test]
fn mixed_work_violation_remains_visible_with_unresolved_worker() {
    const EVENTS: &[Event] = &[
        event(24, 1, EventKind::WorkerStarted { worker_id: 240 }),
        event(24, 2, EventKind::OpenCompleted(OpenOutcome::Failed)),
        event(
            24,
            3,
            EventKind::Refused(RefusalReason::PersistentOpenFailed),
        ),
        event(
            24,
            4,
            EventKind::Work(WorkEvent::Attempted { work_id: 241 }),
        ),
        event(
            24,
            5,
            EventKind::Work(WorkEvent::Admitted { work_id: 241 }),
        ),
    ];
    assessment(
        InitializationTrace {
            initialization_id: 24,
            requested_mode: RequestedMode::Persistent,
            events: EVENTS,
            event_history_complete: true,
        },
        Classification::ContractViolation,
        WorkerTermination::Unresolved,
    );
}

#[test]
fn rejected_submission_is_distinct_from_admitted_or_executed_work() {
    const REJECTED: &[Event] = &[
        event(25, 1, EventKind::OpenCompleted(OpenOutcome::Failed)),
        event(
            25,
            2,
            EventKind::Refused(RefusalReason::PersistentOpenFailed),
        ),
        event(
            25,
            3,
            EventKind::Work(WorkEvent::Attempted { work_id: 250 }),
        ),
        event(
            25,
            4,
            EventKind::Work(WorkEvent::Rejected { work_id: 250 }),
        ),
    ];
    assessment(
        InitializationTrace {
            initialization_id: 25,
            requested_mode: RequestedMode::Persistent,
            events: REJECTED,
            event_history_complete: true,
        },
        Classification::PersistentOpenRefused,
        WorkerTermination::NotStarted,
    );

    for work_outcome in [
        WorkEvent::Admitted { work_id: 260 },
        WorkEvent::Executed { work_id: 260 },
    ] {
        let events = [
            event(26, 1, EventKind::OpenCompleted(OpenOutcome::Failed)),
            event(
                26,
                2,
                EventKind::Refused(RefusalReason::PersistentOpenFailed),
            ),
            event(
                26,
                3,
                EventKind::Work(WorkEvent::Attempted { work_id: 260 }),
            ),
            event(26, 4, EventKind::Work(work_outcome)),
        ];
        assessment(
            InitializationTrace {
                initialization_id: 26,
                requested_mode: RequestedMode::Persistent,
                events: &events,
                event_history_complete: true,
            },
            Classification::ContractViolation,
            WorkerTermination::NotStarted,
        );
    }

}

#[test]
fn attempted_but_unresolved_submission_is_not_assumed_rejected() {
    const EVENTS: &[Event] = &[
        event(30, 1, EventKind::OpenCompleted(OpenOutcome::Failed)),
        event(
            30,
            2,
            EventKind::Refused(RefusalReason::PersistentOpenFailed),
        ),
        event(
            30,
            3,
            EventKind::Work(WorkEvent::Attempted { work_id: 300 }),
        ),
    ];
    assessment(
        InitializationTrace {
            initialization_id: 30,
            requested_mode: RequestedMode::Persistent,
            events: EVENTS,
            event_history_complete: true,
        },
        Classification::Inconclusive,
        WorkerTermination::NotStarted,
    );
}

#[test]
fn pending_timeout_panic_missing_response_and_setup_failure_are_inconclusive() {
    for signal in [
        InitSignal::Pending,
        InitSignal::TimedOut,
        InitSignal::Panicked,
        InitSignal::MissingResponse,
        InitSignal::SetupFailed,
    ] {
        let events = [event(27, 1, EventKind::Signal(signal))];
        assessment(
            InitializationTrace {
                initialization_id: 27,
                requested_mode: RequestedMode::Persistent,
                events: &events,
                event_history_complete: true,
            },
            Classification::Inconclusive,
            WorkerTermination::NotStarted,
        );
    }
}

#[test]
fn incomplete_supplied_history_cannot_establish_refusal() {
    const EVENTS: &[Event] = &[
        event(28, 1, EventKind::OpenCompleted(OpenOutcome::Failed)),
        event(
            28,
            2,
            EventKind::Refused(RefusalReason::PersistentOpenFailed),
        ),
    ];
    assessment(
        InitializationTrace {
            initialization_id: 28,
            requested_mode: RequestedMode::Persistent,
            events: EVENTS,
            event_history_complete: false,
        },
        Classification::Inconclusive,
        WorkerTermination::Unresolved,
    );
}
