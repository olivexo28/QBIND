//! Test-only interface and deterministic storage. No production imports,
//! persistence format, synchronization, fencing, restart or delivery proof.

const MAX_PREFIX: usize = 4;
const MAX_EVIDENCE: usize = 16;
const FIXTURE_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Scope {
    store: u64,
    incarnation: u64,
    operation: u64,
    writer: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Observation {
    Unknown,
    NoEffect,
    Effect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Completion {
    Unknown,
    NoEffect,
    Effect,
    Conflict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Effects {
    known: bool,
    completion: Completion,
}

impl Effects {
    fn unknown() -> Self {
        Self {
            known: false,
            completion: Completion::Unknown,
        }
    }

    fn observe(&mut self, next: Observation) {
        self.known |= next == Observation::Effect;
        let next = match next {
            Observation::Unknown => Completion::Unknown,
            Observation::NoEffect => Completion::NoEffect,
            Observation::Effect => Completion::Effect,
        };
        self.completion = match (self.completion, next) {
            (Completion::Unknown, next) => next,
            (previous, next) if previous == next => previous,
            _ => Completion::Conflict,
        };
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Update {
    version: u8,
    prefix: Vec<u64>,
    // Current item, signing, storage, callbacks, outbound: separate domains.
    domains: [Observation; 5],
    evidence: Vec<u8>,
    complete: bool,
}

impl Update {
    fn unknown(prefix: &[u64]) -> Self {
        Self {
            version: FIXTURE_VERSION,
            prefix: prefix.to_vec(),
            domains: [Observation::Unknown; 5],
            evidence: Vec::new(),
            complete: false,
        }
    }

    fn validate(&self) -> Result<(), Error> {
        if self.version != FIXTURE_VERSION {
            return Err(Error::Unsupported);
        }
        if self.prefix.len() > MAX_PREFIX || self.evidence.len() > MAX_EVIDENCE {
            return Err(Error::Oversized);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Outcome {
    prefix: Vec<u64>,
    prefix_conflict: bool,
    prefix_observations: Vec<Vec<u64>>,
    domains: [Effects; 5],
    evidence: Vec<Vec<u8>>,
    complete_seen: bool,
}

impl Outcome {
    fn empty() -> Self {
        Self {
            prefix: Vec::new(),
            prefix_conflict: false,
            prefix_observations: Vec::new(),
            domains: [Effects::unknown(); 5],
            evidence: Vec::new(),
            complete_seen: false,
        }
    }

    fn merge(&self, update: &Update) -> Result<Self, Error> {
        update.validate()?;
        let mut next = self.clone();
        if !next.prefix_observations.contains(&update.prefix) {
            if next.prefix_observations.len() >= MAX_EVIDENCE {
                return Err(Error::Oversized);
            }
            next.prefix_observations.push(update.prefix.clone());
        }
        if update.prefix.starts_with(&self.prefix) {
            next.prefix.clone_from(&update.prefix);
        } else {
            // Do not discard the accepted prefix on shorter or different input.
            next.prefix_conflict = true;
        }
        for (domain, observation) in next.domains.iter_mut().zip(update.domains) {
            domain.observe(observation);
        }
        if !next.evidence.contains(&update.evidence) {
            // Aggregate fixture bound, not a production retention policy.
            if next.evidence.len() >= MAX_EVIDENCE {
                return Err(Error::Oversized);
            }
            next.evidence.push(update.evidence.clone());
        }
        next.complete_seen |= update.complete;
        Ok(next)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Record {
    scope: Scope,
    revision: u64,
    outcome: Outcome,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Inspection {
    Missing,
    Corrupt,
    Truncated,
    Unsupported,
    Foreign,
    Unreadable,
    Unavailable,
    Valid(Record),
}

impl Inspection {
    fn permits_participation(&self) -> bool {
        // Even a supported local record proves neither currentness nor
        // exclusive signing; this prototype deliberately has no clear API.
        false
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Publication {
    Acknowledged,
    Failed,
    Uncertain,
    VisibleButError,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Error {
    Scope,
    Ownership,
    StaleRevision,
    Existing,
    Unsupported,
    Oversized,
    PublicationUnresolved,
    Barrier,
}

// Private fixture token. Issued only by successful publish_applying; not a
// cryptographic capability or proof of durability/currentness.
#[derive(Debug)]
struct IntentAck {
    scope: Scope,
    intent_revision: u64,
}

#[derive(Debug, PartialEq, Eq)]
struct OutcomeAck {
    scope: Scope,
    revision: u64,
}

#[derive(Debug, PartialEq, Eq)]
struct RecordFailure {
    error: Error,
    // Volatile attempted/observed evidence, NOT acknowledged persistence.
    observed: Option<Outcome>,
}

trait QuarantineStore {
    fn inspect(&self) -> Inspection;
    fn publish_applying(
        &mut self,
        scope: Scope,
        expected_revision: u64,
        version: u8,
        publication: Publication,
    ) -> Result<IntentAck, Error>;
    fn record_outcome(
        &mut self,
        ack: &IntentAck,
        scope: Scope,
        expected_revision: u64,
        update: &Update,
        publication: Publication,
    ) -> Result<OutcomeAck, RecordFailure>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FakeStore {
    store: u64,
    incarnation: u64,
    owner: Option<u64>,
    revision: u64,
    visible: Inspection,
    acknowledged_intent: Option<(Scope, u64)>,
    intent_attempted: bool,
    outcome_attempted: bool,
    // Survives calls in this fake object, not process loss.
    observed: Outcome,
    unresolved: bool,
}

impl FakeStore {
    fn fixture() -> Self {
        Self {
            store: 1,
            incarnation: 2,
            owner: None,
            revision: 0,
            visible: Inspection::Missing,
            acknowledged_intent: None,
            intent_attempted: false,
            outcome_attempted: false,
            observed: Outcome::empty(),
            unresolved: true,
        }
    }

    fn claim(&mut self, writer: u64) -> Result<(), Error> {
        if self.owner.is_some() {
            return Err(Error::Ownership);
        }
        self.owner = Some(writer);
        Ok(())
    }

    fn check_scope(&self, scope: Scope) -> Result<(), Error> {
        if scope.store != self.store || scope.incarnation != self.incarnation {
            return Err(Error::Scope);
        }
        if self.owner != Some(scope.writer) {
            return Err(Error::Ownership);
        }
        Ok(())
    }

    fn mutation_gate(&self, ack: &IntentAck, barrier: bool) -> Result<(), Error> {
        self.check_scope(ack.scope)?;
        if self.acknowledged_intent != Some((ack.scope, ack.intent_revision)) {
            return Err(Error::Scope);
        }
        if !barrier || self.outcome_attempted {
            return Err(Error::Barrier);
        }
        // This is only a fixture barrier check, never participation permission.
        Ok(())
    }

    fn modeled_restart(&self) -> Self {
        let mut restarted = Self::fixture();
        restarted.store = self.store;
        restarted.incarnation = self.incarnation;
        restarted.revision = self.revision;
        restarted.visible = self.visible.clone();
        restarted.intent_attempted = true;
        // No acknowledged token/volatile observations or clear authority
        // reconstructed from a readable local record.
        restarted
    }
}

impl QuarantineStore for FakeStore {
    fn inspect(&self) -> Inspection {
        self.visible.clone()
    }

    fn publish_applying(
        &mut self,
        scope: Scope,
        expected_revision: u64,
        version: u8,
        publication: Publication,
    ) -> Result<IntentAck, Error> {
        self.check_scope(scope)?;
        if version != FIXTURE_VERSION {
            return Err(Error::Unsupported);
        }
        if expected_revision != self.revision {
            return Err(Error::StaleRevision);
        }
        if self.visible != Inspection::Missing || self.intent_attempted {
            return Err(Error::Existing);
        }
        let revision = self.revision.checked_add(1).ok_or(Error::StaleRevision)?;
        self.intent_attempted = true;
        self.unresolved = true;
        if matches!(
            publication,
            Publication::Acknowledged | Publication::VisibleButError
        ) {
            self.visible = Inspection::Valid(Record {
                scope,
                revision,
                outcome: Outcome::empty(),
            });
            self.revision = revision;
        }
        if publication != Publication::Acknowledged {
            return Err(Error::PublicationUnresolved);
        }
        self.acknowledged_intent = Some((scope, revision));
        Ok(IntentAck {
            scope,
            intent_revision: revision,
        })
    }

    fn record_outcome(
        &mut self,
        ack: &IntentAck,
        scope: Scope,
        expected_revision: u64,
        update: &Update,
        publication: Publication,
    ) -> Result<OutcomeAck, RecordFailure> {
        let validate = || {
            self.check_scope(scope)?;
            if ack.scope != scope || self.acknowledged_intent != Some((scope, ack.intent_revision))
            {
                return Err(Error::Scope);
            }
            if expected_revision != self.revision {
                return Err(Error::StaleRevision);
            }
            self.revision.checked_add(1).ok_or(Error::StaleRevision)
        };
        let revision = validate().map_err(|error| RecordFailure {
            error,
            observed: None,
        })?;
        let merged = self.observed.merge(update).map_err(|error| RecordFailure {
            error,
            observed: None,
        })?;
        self.outcome_attempted = true;
        self.observed = merged.clone();
        self.unresolved = true;
        if matches!(
            publication,
            Publication::Acknowledged | Publication::VisibleButError
        ) {
            self.visible = Inspection::Valid(Record {
                scope,
                revision,
                outcome: merged.clone(),
            });
            self.revision = revision;
        }
        if publication != Publication::Acknowledged {
            return Err(RecordFailure {
                error: Error::PublicationUnresolved,
                observed: Some(merged),
            });
        }
        Ok(OutcomeAck { scope, revision })
    }
}

fn scope() -> Scope {
    Scope {
        store: 1,
        incarnation: 2,
        operation: 3,
        writer: 4,
    }
}

fn prepared() -> (FakeStore, IntentAck) {
    let mut store = FakeStore::fixture();
    store.claim(4).unwrap();
    let ack = store
        .publish_applying(scope(), 0, FIXTURE_VERSION, Publication::Acknowledged)
        .unwrap();
    (store, ack)
}

#[test]
fn inspection_is_read_only_and_every_local_class_stays_closed() {
    let (valid, _) = prepared();
    for observation in [
        Inspection::Missing,
        Inspection::Corrupt,
        Inspection::Truncated,
        Inspection::Unsupported,
        Inspection::Foreign,
        Inspection::Unreadable,
        Inspection::Unavailable,
        valid.inspect(),
    ] {
        let mut store = FakeStore::fixture();
        store.visible = observation.clone();
        let before = store.clone();
        assert_eq!(store.inspect(), observation);
        assert!(!store.inspect().permits_participation());
        assert_eq!(store, before);
    }
}

#[test]
fn failed_uncertain_and_visible_error_publication_issue_no_ack() {
    for publication in [
        Publication::Failed,
        Publication::Uncertain,
        Publication::VisibleButError,
    ] {
        let mut store = FakeStore::fixture();
        store.claim(4).unwrap();
        assert_eq!(
            store
                .publish_applying(scope(), 0, FIXTURE_VERSION, publication)
                .unwrap_err(),
            Error::PublicationUnresolved
        );
        assert_eq!(store.acknowledged_intent, None);
        assert_eq!(
            matches!(store.inspect(), Inspection::Valid(_)),
            publication == Publication::VisibleButError
        );
        assert!(store.unresolved);
        assert!(!store.inspect().permits_participation());
        assert!(store
            .publish_applying(
                scope(),
                store.revision,
                FIXTURE_VERSION,
                Publication::Acknowledged
            )
            .is_err());
    }
}

#[test]
fn acknowledgements_bind_every_scope_field_and_store_incarnation() {
    for changed in [
        Scope {
            store: 9,
            ..scope()
        },
        Scope {
            incarnation: 9,
            ..scope()
        },
        Scope {
            operation: 9,
            ..scope()
        },
        Scope {
            writer: 9,
            ..scope()
        },
    ] {
        let (mut store, ack) = prepared();
        let before = store.clone();
        assert!(store
            .record_outcome(
                &ack,
                changed,
                1,
                &Update::unknown(&[]),
                Publication::Acknowledged
            )
            .is_err());
        assert_eq!(store, before);
        let mut other = FakeStore::fixture();
        other.store = changed.store;
        other.incarnation = changed.incarnation;
        other.claim(changed.writer).unwrap();
        assert!(other
            .record_outcome(
                &ack,
                changed,
                0,
                &Update::unknown(&[]),
                Publication::Acknowledged
            )
            .is_err());
    }
    let (store, ack) = prepared();
    let mut reincarnated = store.clone();
    reincarnated.incarnation += 1;
    assert!(reincarnated
        .record_outcome(
            &ack,
            scope(),
            1,
            &Update::unknown(&[]),
            Publication::Acknowledged
        )
        .is_err());
}

#[test]
fn writer_serialization_and_revision_compare_are_fixture_local_only() {
    let (mut store, ack) = prepared();
    assert_eq!(store.claim(5), Err(Error::Ownership));
    let before = store.clone();
    assert_eq!(
        store
            .publish_applying(scope(), 0, FIXTURE_VERSION, Publication::Acknowledged)
            .unwrap_err(),
        Error::StaleRevision
    );
    assert_eq!(
        store
            .publish_applying(scope(), 1, FIXTURE_VERSION, Publication::Acknowledged)
            .unwrap_err(),
        Error::Existing
    );
    assert_eq!(
        store
            .record_outcome(
                &ack,
                scope(),
                0,
                &Update::unknown(&[]),
                Publication::Acknowledged
            )
            .unwrap_err()
            .error,
        Error::StaleRevision
    );
    assert_eq!(store, before);
    let mut copy = FakeStore::fixture();
    copy.claim(5).unwrap();
    assert_eq!(copy.owner, Some(5)); // No shared cross-copy fence.
    assert!(!copy.inspect().permits_participation());
}

#[test]
fn intent_acknowledgement_is_not_a_barrier_or_participation_authority() {
    let (store, ack) = prepared();
    assert_eq!(store.mutation_gate(&ack, false), Err(Error::Barrier));
    assert_eq!(store.mutation_gate(&ack, true), Ok(()));
    assert!(!store.inspect().permits_participation());
    assert!(store.unresolved);
}

#[test]
fn outcomes_keep_prefix_and_separate_sticky_domains() {
    let (mut store, ack) = prepared();
    let mut update = Update::unknown(&[10, 11]);
    update.domains = [
        Observation::Unknown,
        Observation::Effect,
        Observation::Unknown,
        Observation::NoEffect,
        Observation::Effect,
    ];
    store
        .record_outcome(&ack, scope(), 1, &update, Publication::Acknowledged)
        .unwrap();
    assert_eq!(store.observed.domains[0].completion, Completion::Unknown);
    assert_eq!(store.observed.domains[2].completion, Completion::Unknown);
    assert_eq!(store.observed.domains[3].completion, Completion::NoEffect);
    update.prefix = vec![10];
    update.domains = [Observation::NoEffect; 5];
    store
        .record_outcome(&ack, scope(), 2, &update, Publication::Acknowledged)
        .unwrap();
    assert_eq!(store.observed.prefix, vec![10, 11]);
    assert!(store.observed.prefix_conflict);
    assert_eq!(
        store.observed.prefix_observations,
        vec![vec![10, 11], vec![10]]
    );
    assert_eq!(store.observed.domains[0].completion, Completion::NoEffect);
    for index in [1, 4] {
        assert!(store.observed.domains[index].known);
        assert_eq!(
            store.observed.domains[index].completion,
            Completion::Conflict
        );
    }
    assert_eq!(store.observed.domains[2].completion, Completion::NoEffect);
    assert!(!store.observed.domains[2].known);
}

#[test]
fn repeated_late_and_out_of_order_updates_cannot_erase_effects() {
    for domain in 0..5 {
        let (mut store, ack) = prepared();
        let mut update = Update::unknown(&[10]);
        update.domains[domain] = Observation::Effect;
        for observation in [
            Observation::Effect,
            Observation::Effect,
            Observation::Unknown,
            Observation::NoEffect,
            Observation::Effect,
        ] {
            update.domains[domain] = observation;
            let revision = store.revision;
            store
                .record_outcome(&ack, scope(), revision, &update, Publication::Acknowledged)
                .unwrap();
            assert!(store.observed.domains[domain].known);
        }
        assert_eq!(
            store.observed.domains[domain].completion,
            Completion::Conflict
        );
        assert_eq!(store.observed.prefix, vec![10]);
        assert!(store.unresolved);
    }
}

#[test]
fn failed_outcome_recording_is_not_acknowledged_recorded_uncertainty() {
    for publication in [
        Publication::Failed,
        Publication::Uncertain,
        Publication::VisibleButError,
    ] {
        let (mut store, ack) = prepared();
        let before = store.inspect();
        let mut update = Update::unknown(&[10]);
        update.domains[1] = Observation::Effect;
        let failure = store
            .record_outcome(&ack, scope(), 1, &update, publication)
            .unwrap_err();
        assert_eq!(failure.error, Error::PublicationUnresolved);
        assert_eq!(failure.observed, Some(store.observed.clone()));
        assert!(store.observed.domains[1].known);
        if publication != Publication::VisibleButError {
            assert_eq!(store.inspect(), before);
        }
        // Retry with unknown observations preserves volatile known effects;
        // this is not recovery of observations lost in a process crash.
        let revision = store.revision;
        store
            .record_outcome(
                &ack,
                scope(),
                revision,
                &Update::unknown(&[10]),
                Publication::Acknowledged,
            )
            .unwrap();
        assert!(store.observed.domains[1].known);
        assert_eq!(store.observed.domains[1].completion, Completion::Conflict);
        assert!(store.unresolved);
    }
}

#[test]
fn complete_no_effect_timeout_late_completion_and_restart_never_clear() {
    let (mut store, ack) = prepared();
    let mut update = Update::unknown(&[]);
    update.domains = [Observation::NoEffect; 5];
    update.complete = true;
    store
        .record_outcome(&ack, scope(), 1, &update, Publication::Acknowledged)
        .unwrap();
    // Timeout is only an unknown observation, not worker completion.
    store
        .record_outcome(
            &ack,
            scope(),
            2,
            &Update::unknown(&[]),
            Publication::Acknowledged,
        )
        .unwrap();
    update.domains[1] = Observation::Effect;
    store
        .record_outcome(&ack, scope(), 3, &update, Publication::Acknowledged)
        .unwrap();
    assert!(store.observed.complete_seen);
    assert!(store.unresolved);
    assert!(!store.inspect().permits_participation());
    let mut restart = store.modeled_restart();
    assert!(!restart.inspect().permits_participation());
    assert!(restart.unresolved);
    assert!(restart
        .record_outcome(&ack, scope(), 4, &update, Publication::Acknowledged)
        .is_err());
}

#[test]
fn fixture_bounds_versions_and_overflow_refuse_without_truncation() {
    let (mut store, ack) = prepared();
    for update in [
        Update {
            prefix: vec![1; MAX_PREFIX + 1],
            ..Update::unknown(&[])
        },
        Update {
            evidence: vec![1; MAX_EVIDENCE + 1],
            ..Update::unknown(&[])
        },
        Update {
            version: 2,
            ..Update::unknown(&[])
        },
    ] {
        let before = store.clone();
        assert!(store
            .record_outcome(&ack, scope(), 1, &update, Publication::Acknowledged)
            .is_err());
        assert_eq!(store, before);
    }
    for index in 0..MAX_EVIDENCE {
        let update = Update {
            evidence: vec![index as u8],
            ..Update::unknown(&[])
        };
        let revision = store.revision;
        store
            .record_outcome(&ack, scope(), revision, &update, Publication::Acknowledged)
            .unwrap();
    }
    let before = store.clone();
    assert_eq!(
        store
            .record_outcome(
                &ack,
                scope(),
                store.revision,
                &Update {
                    evidence: vec![255],
                    ..Update::unknown(&[])
                },
                Publication::Acknowledged
            )
            .unwrap_err()
            .error,
        Error::Oversized
    );
    assert_eq!(store, before);
    store.revision = u64::MAX;
    assert_eq!(
        store
            .record_outcome(
                &ack,
                scope(),
                u64::MAX,
                &Update::unknown(&[]),
                Publication::Acknowledged
            )
            .unwrap_err()
            .error,
        Error::StaleRevision
    );
    let mut fresh = FakeStore::fixture();
    fresh.claim(4).unwrap();
    assert_eq!(
        fresh
            .publish_applying(scope(), 0, 2, Publication::Acknowledged)
            .unwrap_err(),
        Error::Unsupported
    );
    assert_eq!(fresh.inspect(), Inspection::Missing);
}

#[test]
fn rejected_or_stale_scope_never_mutates_acknowledged_outcomes() {
    let (mut store, ack) = prepared();
    let update = Update::unknown(&[10]);
    let receipt = store
        .record_outcome(&ack, scope(), 1, &update, Publication::Acknowledged)
        .unwrap();
    assert_eq!(
        receipt,
        OutcomeAck {
            scope: scope(),
            revision: 2
        }
    );
    let before = store.clone();
    assert_eq!(
        store
            .record_outcome(&ack, scope(), 1, &update, Publication::Acknowledged)
            .unwrap_err()
            .error,
        Error::StaleRevision
    );
    let wrong_revision = IntentAck {
        scope: scope(),
        intent_revision: 2,
    };
    assert_eq!(
        store
            .record_outcome(
                &wrong_revision,
                scope(),
                2,
                &update,
                Publication::Acknowledged
            )
            .unwrap_err()
            .error,
        Error::Scope
    );
    assert_eq!(store, before);
}

#[test]
fn unreadable_or_uncertain_restart_does_not_initialize_a_clean_marker() {
    for observation in [
        Inspection::Corrupt,
        Inspection::Truncated,
        Inspection::Unsupported,
        Inspection::Foreign,
        Inspection::Unreadable,
        Inspection::Unavailable,
    ] {
        let mut store = FakeStore::fixture();
        store.visible = observation;
        store.claim(4).unwrap();
        let before = store.clone();
        assert_eq!(
            store
                .publish_applying(scope(), 0, FIXTURE_VERSION, Publication::Acknowledged)
                .unwrap_err(),
            Error::Existing
        );
        assert_eq!(store, before);
    }
    let mut store = FakeStore::fixture();
    store.claim(4).unwrap();
    assert!(store
        .publish_applying(scope(), 0, FIXTURE_VERSION, Publication::Uncertain)
        .is_err());
    let mut restart = store.modeled_restart();
    restart.claim(4).unwrap();
    assert!(restart
        .publish_applying(scope(), 0, FIXTURE_VERSION, Publication::Acknowledged)
        .is_err());
    assert_eq!(restart.inspect(), Inspection::Missing);
    assert!(!restart.inspect().permits_participation());
}

#[test]
fn normal_consistent_updates_extend_prefix_without_resolving_other_domains() {
    let (mut store, ack) = prepared();
    let mut update = Update::unknown(&[10]);
    update.domains[1] = Observation::Effect;
    for prefix in [vec![10], vec![10], vec![10, 11]] {
        update.prefix = prefix;
        let revision = store.revision;
        store
            .record_outcome(&ack, scope(), revision, &update, Publication::Acknowledged)
            .unwrap();
    }
    assert_eq!(store.observed.prefix, vec![10, 11]);
    assert!(!store.observed.prefix_conflict);
    assert_eq!(store.observed.domains[1].completion, Completion::Effect);
    for index in [0, 2, 3, 4] {
        assert_eq!(
            store.observed.domains[index].completion,
            Completion::Unknown
        );
    }
    assert!(!store.inspect().permits_participation());
}

#[test]
fn token_from_another_acknowledged_operation_or_writer_is_rejected() {
    let (_, original) = prepared();
    for changed in [
        Scope {
            store: 8,
            ..scope()
        },
        Scope {
            incarnation: 8,
            ..scope()
        },
        Scope {
            operation: 8,
            ..scope()
        },
        Scope {
            writer: 8,
            ..scope()
        },
    ] {
        let mut other = FakeStore::fixture();
        other.store = changed.store;
        other.incarnation = changed.incarnation;
        other.claim(changed.writer).unwrap();
        let own = other
            .publish_applying(changed, 0, FIXTURE_VERSION, Publication::Acknowledged)
            .unwrap();
        let before = other.clone();
        assert!(other
            .record_outcome(
                &original,
                changed,
                1,
                &Update::unknown(&[]),
                Publication::Acknowledged
            )
            .is_err());
        assert_eq!(other, before);
        assert!(other
            .record_outcome(
                &own,
                changed,
                1,
                &Update::unknown(&[]),
                Publication::Acknowledged
            )
            .is_ok());
    }
}

#[test]
fn outcome_attempts_never_reauthorize_fixture_mutation_even_on_error() {
    for publication in [
        Publication::Acknowledged,
        Publication::Failed,
        Publication::Uncertain,
        Publication::VisibleButError,
    ] {
        let (mut store, ack) = prepared();
        let _result = store.record_outcome(&ack, scope(), 1, &Update::unknown(&[]), publication);
        assert_eq!(store.mutation_gate(&ack, true), Err(Error::Barrier));
        assert!(!store.inspect().permits_participation());
        assert!(store.unresolved);
    }
}
