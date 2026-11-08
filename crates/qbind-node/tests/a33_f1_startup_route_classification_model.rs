//! A33-F1 — isolated startup route/classification ordering model.
//!
//! This is a synthetic test-only trace checker, not a CLI/startup test. Source
//! events are anchored to main `0d1b56515c52abe2862064027d1a9f103fef5a0c`;
//! classification/admission events are future requirements only. The model
//! neither acquires a destination lock nor grants production authority.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    NormalWithDataDir,
    RequestedRestore,
    Reset,
    NoDataDir,
    EarlyExit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IdentityEvidence {
    SyntheticTrustedFixture,
    Unavailable,
    Untrusted,
    DisplayFingerprintOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IdentityClaims {
    destination: IdentityEvidence,
    chain: IdentityEvidence,
    genesis: IdentityEvidence,
    signer: IdentityEvidence,
}

impl IdentityClaims {
    fn synthetic_trusted() -> Self {
        Self {
            destination: IdentityEvidence::SyntheticTrustedFixture,
            chain: IdentityEvidence::SyntheticTrustedFixture,
            genesis: IdentityEvidence::SyntheticTrustedFixture,
            signer: IdentityEvidence::SyntheticTrustedFixture,
        }
    }

    fn can_admit_synthetic_trace(self) -> bool {
        self.destination == IdentityEvidence::SyntheticTrustedFixture
            && self.chain == IdentityEvidence::SyntheticTrustedFixture
            && self.genesis == IdentityEvidence::SyntheticTrustedFixture
            && self.signer == IdentityEvidence::SyntheticTrustedFixture
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClassificationDecision {
    AdmitSyntheticTrace,
    Refuse,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecordObservation {
    Absent,
    CorruptOrInvalid,
    Unreadable,
    ForeignOrAmbiguous,
    Unresolved,
    SyntheticPositiveFixture,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PreExitEffect {
    IdentityUtilityWroteFiles,
    GenesisHashUtilityReadGenesis,
    BootConfigurationRead,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    DataDirectoryCreated,
    NormalDestinationOwned,
    ResetDestinationOwned,
    Classified {
        record: RecordObservation,
        identity: IdentityClaims,
        decision: ClassificationDecision,
    },
    ConsensusStorageOpened,
    RestoreRecordChecked,
    RestoreIntentPublished,
    AccountStateMaterialized,
    SnapshotEpochPersisted,
    RestoreCompletePublished,
    ResetMutation,
    MetricsTaskSpawned,
    SignerLoaded,
    P2pListenerStarted,
    SnapshotWorkerStarted,
    ConsensusLoopStarted,
    ParticipationAuthorityProduced,
    PreExitEffect(PreExitEffect),
    Exit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Violation {
    MissingOrMisorderedDirectoryCreation,
    MissingOrMisorderedOwnership,
    WrongOwnershipBoundary,
    MissingOrRepeatedClassification,
    ClassificationBeforeOwnership,
    IdentityCannotSupportAdmission,
    RefusalModelAdmitted,
    ProtectedEffectBeforeClassification,
    ParticipationWithoutAdmission,
    StatelessRouteHasOwnershipOrParticipation,
    EarlyExitHasProtectedEffect,
    ExitNotLast,
    RestoreEffectsOutOfOrder,
    StatelessIdentityNotUnavailable,
    EarlyExitCrossedStartupBoundary,
    RecordObservationCannotAdmit,
    ProtectedEffectAfterRefusal,
    NormalMetricsStorageOrder,
}

fn is_protected_effect(event: Event) -> bool {
    matches!(
        event,
        Event::ConsensusStorageOpened
            | Event::RestoreRecordChecked
            | Event::RestoreIntentPublished
            | Event::AccountStateMaterialized
            | Event::SnapshotEpochPersisted
            | Event::RestoreCompletePublished
            | Event::ResetMutation
            | Event::MetricsTaskSpawned
            | Event::SignerLoaded
            | Event::P2pListenerStarted
            | Event::SnapshotWorkerStarted
            | Event::ConsensusLoopStarted
            | Event::ParticipationAuthorityProduced
    )
}

fn position(events: &[Event], wanted: Event) -> Option<usize> {
    events.iter().position(|event| *event == wanted)
}

fn check_trace(route: Route, events: &[Event]) -> Vec<Violation> {
    let mut violations = Vec::new();
    let directory = position(events, Event::DataDirectoryCreated);
    let normal_owner = position(events, Event::NormalDestinationOwned);
    let reset_owner = position(events, Event::ResetDestinationOwned);
    let normal_owner_count = events
        .iter()
        .filter(|event| **event == Event::NormalDestinationOwned)
        .count();
    let reset_owner_count = events
        .iter()
        .filter(|event| **event == Event::ResetDestinationOwned)
        .count();
    let classifications: Vec<(
        usize,
        RecordObservation,
        IdentityClaims,
        ClassificationDecision,
    )> = events
        .iter()
        .enumerate()
        .filter_map(|(index, event)| match event {
            Event::Classified {
                record,
                identity,
                decision,
            } => Some((index, *record, *identity, *decision)),
            _ => None,
        })
        .collect();
    let classification = classifications.first().copied();

    if classifications.len() > 1 {
        violations.push(Violation::MissingOrRepeatedClassification);
    }

    match route {
        Route::NormalWithDataDir | Route::RequestedRestore => {
            match (directory, normal_owner) {
                (Some(dir), Some(owner)) if dir < owner => {}
                _ => violations.push(Violation::MissingOrMisorderedDirectoryCreation),
            }
            if normal_owner.is_none() {
                violations.push(Violation::MissingOrMisorderedOwnership);
            }
            if reset_owner.is_some() || normal_owner_count > 1 || reset_owner_count > 0 {
                violations.push(Violation::WrongOwnershipBoundary);
            }
            if classification.is_none() {
                violations.push(Violation::MissingOrRepeatedClassification);
            } else if let (Some(owner), Some((class_index, _, _, _))) =
                (normal_owner, classification)
            {
                if class_index < owner {
                    violations.push(Violation::ClassificationBeforeOwnership);
                }
            }
        }
        Route::Reset => {
            match (directory, reset_owner) {
                (Some(dir), Some(owner)) if dir < owner => {}
                _ => violations.push(Violation::MissingOrMisorderedDirectoryCreation),
            }
            if reset_owner.is_none() {
                violations.push(Violation::MissingOrMisorderedOwnership);
            }
            if normal_owner.is_some() || reset_owner_count > 1 || normal_owner_count > 0 {
                violations.push(Violation::WrongOwnershipBoundary);
            }
            if classification.is_none() {
                violations.push(Violation::MissingOrRepeatedClassification);
            } else if let (Some(owner), Some((class_index, _, _, _))) =
                (reset_owner, classification)
            {
                if class_index < owner {
                    violations.push(Violation::ClassificationBeforeOwnership);
                }
            }
        }
        Route::NoDataDir => {
            if directory.is_some() || normal_owner.is_some() || reset_owner.is_some() {
                violations.push(Violation::StatelessRouteHasOwnershipOrParticipation);
            }
            if classification.is_none() {
                violations.push(Violation::MissingOrRepeatedClassification);
            } else if let Some((_, record, identity, decision)) = classification {
                if identity.destination != IdentityEvidence::Unavailable
                    || decision != ClassificationDecision::Refuse
                    || record != RecordObservation::Absent
                {
                    violations.push(Violation::StatelessIdentityNotUnavailable);
                }
            }
        }
        Route::EarlyExit => {
            if classifications.len() > 0 || normal_owner.is_some() || reset_owner.is_some() {
                violations.push(Violation::EarlyExitCrossedStartupBoundary);
            }
        }
    }

    if let Some((_, record, identity, decision)) = classification {
        let identity_trusted = identity.can_admit_synthetic_trace();
        match decision {
            ClassificationDecision::AdmitSyntheticTrace => {
                if !identity_trusted {
                    violations.push(Violation::IdentityCannotSupportAdmission);
                }
                if record != RecordObservation::SyntheticPositiveFixture {
                    violations.push(Violation::RecordObservationCannotAdmit);
                }
            }
            ClassificationDecision::Refuse => {}
        }
        if route == Route::NoDataDir && decision != ClassificationDecision::Refuse {
            violations.push(Violation::RefusalModelAdmitted);
        }
    }

    for (index, event) in events.iter().copied().enumerate() {
        if !is_protected_effect(event) {
            continue;
        }
        match classification {
            Some((class_index, record, identity, ClassificationDecision::AdmitSyntheticTrace))
                if class_index < index
                    && record == RecordObservation::SyntheticPositiveFixture
                    && identity.can_admit_synthetic_trace() =>
            {
                if matches!(route, Route::NoDataDir | Route::EarlyExit) {
                    violations.push(Violation::StatelessRouteHasOwnershipOrParticipation);
                }
            }
            Some((class_index, _, _, ClassificationDecision::Refuse)) if class_index < index => {
                violations.push(Violation::ProtectedEffectAfterRefusal);
            }
            _ => violations.push(Violation::ProtectedEffectBeforeClassification),
        }
    }

    let participation = position(events, Event::ParticipationAuthorityProduced);
    if participation.is_some()
        && (route != Route::NormalWithDataDir && route != Route::RequestedRestore
            || !matches!(
                classification,
                Some((
                    index,
                    RecordObservation::SyntheticPositiveFixture,
                    identity,
                    ClassificationDecision::AdmitSyntheticTrace
                ))
                    if index < participation.unwrap()
                        && identity.can_admit_synthetic_trace()
            ))
    {
        violations.push(Violation::ParticipationWithoutAdmission);
    }

    match route {
        Route::RequestedRestore => {
            let restore_order = [
                Event::ConsensusStorageOpened,
                Event::RestoreRecordChecked,
                Event::RestoreIntentPublished,
                Event::AccountStateMaterialized,
                Event::SnapshotEpochPersisted,
                Event::RestoreCompletePublished,
            ];
            let indices: Vec<Option<usize>> = restore_order
                .iter()
                .map(|event| position(events, *event))
                .collect();
            if indices.iter().any(Option::is_none)
                || indices.windows(2).any(|pair| pair[0] >= pair[1])
            {
                violations.push(Violation::RestoreEffectsOutOfOrder);
            }
        }
        Route::Reset => {
            if let (Some(class_index), Some(reset_index)) = (
                classification.map(|(index, _, _, _)| index),
                position(events, Event::ResetMutation),
            ) {
                if class_index >= reset_index {
                    violations.push(Violation::ProtectedEffectBeforeClassification);
                }
            }
        }
        Route::NoDataDir | Route::EarlyExit => {
            if events.iter().any(|event| is_protected_effect(*event)) {
                violations.push(if route == Route::EarlyExit {
                    Violation::EarlyExitHasProtectedEffect
                } else {
                    Violation::StatelessRouteHasOwnershipOrParticipation
                });
            }
            if !matches!(events.last(), Some(Event::Exit)) {
                violations.push(Violation::ExitNotLast);
            }
        }
        Route::NormalWithDataDir => {
            if let (Some(metrics), Some(storage)) = (
                position(events, Event::MetricsTaskSpawned),
                position(events, Event::ConsensusStorageOpened),
            ) {
                if metrics >= storage {
                    violations.push(Violation::NormalMetricsStorageOrder);
                }
            }
        }
    }

    violations.dedup();
    violations
}

fn admitted(identity: IdentityClaims) -> Event {
    Event::Classified {
        record: RecordObservation::SyntheticPositiveFixture,
        identity,
        decision: ClassificationDecision::AdmitSyntheticTrace,
    }
}

fn refused(record: RecordObservation, identity: IdentityClaims) -> Event {
    Event::Classified {
        record,
        identity,
        decision: ClassificationDecision::Refuse,
    }
}

#[test]
fn positive_normal_ordering_keeps_directory_creation_before_ownership() {
    let events = [
        Event::DataDirectoryCreated,
        Event::NormalDestinationOwned,
        admitted(IdentityClaims::synthetic_trusted()),
        Event::MetricsTaskSpawned,
        Event::ConsensusStorageOpened,
        Event::SignerLoaded,
        Event::P2pListenerStarted,
        Event::SnapshotWorkerStarted,
        Event::ConsensusLoopStarted,
        Event::ParticipationAuthorityProduced,
    ];
    assert!(check_trace(Route::NormalWithDataDir, &events).is_empty());
}

#[test]
fn positive_restore_ordering_preserves_the_restore_effect_sequence() {
    let events = [
        Event::DataDirectoryCreated,
        Event::NormalDestinationOwned,
        admitted(IdentityClaims::synthetic_trusted()),
        Event::ConsensusStorageOpened,
        Event::RestoreRecordChecked,
        Event::RestoreIntentPublished,
        Event::AccountStateMaterialized,
        Event::SnapshotEpochPersisted,
        Event::RestoreCompletePublished,
        Event::MetricsTaskSpawned,
        Event::ParticipationAuthorityProduced,
    ];
    assert!(check_trace(Route::RequestedRestore, &events).is_empty());
}

#[test]
fn positive_reset_ordering_uses_its_own_owner_and_classification() {
    let events = [
        Event::DataDirectoryCreated,
        Event::ResetDestinationOwned,
        admitted(IdentityClaims::synthetic_trusted()),
        Event::ResetMutation,
        Event::Exit,
    ];
    assert!(check_trace(Route::Reset, &events).is_empty());
}

#[test]
fn stateless_and_untrusted_identity_traces_refuse_without_authority() {
    let no_data_dir = [
        refused(
            RecordObservation::Absent,
            IdentityClaims {
                destination: IdentityEvidence::Unavailable,
                ..IdentityClaims::synthetic_trusted()
            },
        ),
        Event::Exit,
    ];
    assert!(check_trace(Route::NoDataDir, &no_data_dir).is_empty());

    for evidence in [
        IdentityEvidence::Unavailable,
        IdentityEvidence::Untrusted,
        IdentityEvidence::DisplayFingerprintOnly,
    ] {
        for field in 0..4 {
            let mut identity = IdentityClaims::synthetic_trusted();
            match field {
                0 => identity.destination = evidence,
                1 => identity.chain = evidence,
                2 => identity.genesis = evidence,
                _ => identity.signer = evidence,
            }
            let events = [
                Event::DataDirectoryCreated,
                Event::NormalDestinationOwned,
                refused(RecordObservation::SyntheticPositiveFixture, identity),
                Event::Exit,
            ];
            assert!(check_trace(Route::NormalWithDataDir, &events).is_empty());
        }
    }
}

#[test]
fn early_exits_preserve_prior_observable_effects_without_participation() {
    for effect in [
        PreExitEffect::IdentityUtilityWroteFiles,
        PreExitEffect::GenesisHashUtilityReadGenesis,
        PreExitEffect::BootConfigurationRead,
    ] {
        let events = [Event::PreExitEffect(effect), Event::Exit];
        assert!(check_trace(Route::EarlyExit, &events).is_empty());
        assert_eq!(events[0], Event::PreExitEffect(effect));
        assert!(!events.contains(&Event::ParticipationAuthorityProduced));
    }
}

#[test]
fn normal_classification_omission_mutant_is_detected() {
    let mutant = [
        Event::DataDirectoryCreated,
        Event::NormalDestinationOwned,
        Event::MetricsTaskSpawned,
        Event::ConsensusStorageOpened,
        Event::ParticipationAuthorityProduced,
    ];
    let violations = check_trace(Route::NormalWithDataDir, &mutant);
    assert!(violations.contains(&Violation::MissingOrRepeatedClassification));
    assert!(violations.contains(&Violation::ProtectedEffectBeforeClassification));
    assert!(violations.contains(&Violation::ParticipationWithoutAdmission));
}

#[test]
fn normal_classification_misordering_mutant_is_detected() {
    let mutant = [
        Event::DataDirectoryCreated,
        Event::NormalDestinationOwned,
        Event::ConsensusStorageOpened,
        admitted(IdentityClaims::synthetic_trusted()),
        Event::ParticipationAuthorityProduced,
    ];
    let violations = check_trace(Route::NormalWithDataDir, &mutant);
    assert!(violations.contains(&Violation::ProtectedEffectBeforeClassification));
}

#[test]
fn normal_metrics_task_must_precede_consensus_storage() {
    let reversed = [
        Event::DataDirectoryCreated,
        Event::NormalDestinationOwned,
        admitted(IdentityClaims::synthetic_trusted()),
        Event::ConsensusStorageOpened,
        Event::MetricsTaskSpawned,
    ];
    let violations = check_trace(Route::NormalWithDataDir, &reversed);
    assert!(violations.contains(&Violation::NormalMetricsStorageOrder));
}

#[test]
fn record_refusal_observations_cannot_be_forced_into_admission() {
    for record in [
        RecordObservation::Absent,
        RecordObservation::CorruptOrInvalid,
        RecordObservation::Unreadable,
        RecordObservation::ForeignOrAmbiguous,
        RecordObservation::Unresolved,
    ] {
        let valid_refusal = [
            Event::DataDirectoryCreated,
            Event::NormalDestinationOwned,
            refused(record, IdentityClaims::synthetic_trusted()),
            Event::Exit,
        ];
        assert!(
            check_trace(Route::NormalWithDataDir, &valid_refusal).is_empty(),
            "valid refusal trace rejected for {record:?}"
        );

        let forced_admission = [
            Event::DataDirectoryCreated,
            Event::NormalDestinationOwned,
            Event::Classified {
                record,
                identity: IdentityClaims::synthetic_trusted(),
                decision: ClassificationDecision::AdmitSyntheticTrace,
            },
            Event::Exit,
        ];
        assert!(
            check_trace(Route::NormalWithDataDir, &forced_admission)
                .contains(&Violation::RecordObservationCannotAdmit),
            "forced admission accepted for {record:?}"
        );

        let effect_after_refusal = [
            Event::DataDirectoryCreated,
            Event::NormalDestinationOwned,
            refused(record, IdentityClaims::synthetic_trusted()),
            Event::ConsensusStorageOpened,
            Event::Exit,
        ];
        assert!(
            check_trace(Route::NormalWithDataDir, &effect_after_refusal)
                .contains(&Violation::ProtectedEffectAfterRefusal),
            "protected effect accepted after refusal for {record:?}"
        );
    }
}

#[test]
fn reset_classification_omission_mutant_is_detected() {
    let mutant = [
        Event::DataDirectoryCreated,
        Event::ResetDestinationOwned,
        Event::ResetMutation,
    ];
    let violations = check_trace(Route::Reset, &mutant);
    assert!(violations.contains(&Violation::MissingOrRepeatedClassification));
    assert!(violations.contains(&Violation::ProtectedEffectBeforeClassification));
}

#[test]
fn reset_classification_misordering_mutant_is_detected() {
    let mutant = [
        Event::DataDirectoryCreated,
        Event::ResetDestinationOwned,
        Event::ResetMutation,
        admitted(IdentityClaims::synthetic_trusted()),
    ];
    let violations = check_trace(Route::Reset, &mutant);
    assert!(violations.contains(&Violation::ProtectedEffectBeforeClassification));
}
