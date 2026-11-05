//! Test-only state machine, not node enforcement. Store acknowledgements,
//! synchronization, restart, workers and engine effects are deterministic
//! fixtures. They prove no filesystem durability, startup coverage, signer
//! fencing, consensus behavior, process-crash safety or network delivery.

use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Observation {
    Unknown,
    NoEffect,
    EffectObserved,
    EffectUnresolved,
    Conflict,
}

impl Observation {
    fn resolved(self) -> bool {
        matches!(self, Self::NoEffect | Self::EffectObserved)
    }

    fn merge_completion(self, next: Self) -> Self {
        assert!(matches!(
            next,
            Self::Unknown | Self::NoEffect | Self::EffectObserved
        ));
        match (self, next) {
            (Self::Unknown, next) => next,
            (previous, next) if previous == next => previous,
            _ => Self::Conflict,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MarkerRead {
    Missing,
    Corrupt,
    Unsupported,
    Foreign,
    StorageAbsent,
    IoFailure,
    Uncertain,
    ParsedClean,
    ParsedApplying,
    ParsedComplete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Publication {
    Acknowledged,
    FailedBeforePublication,
    VisibleButError,
    Uncertain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Receipt {
    store: u8,
    writer: u8,
}

#[derive(Clone, Debug)]
struct MockStore {
    identity: u8,
    owner: Option<u8>,
    visible_intent: Option<Receipt>,
    visible_outcome: Option<ApplyReport>,
}

impl MockStore {
    fn new(identity: u8) -> Self {
        Self {
            identity,
            owner: None,
            visible_intent: None,
            visible_outcome: None,
        }
    }

    fn claim(&mut self, writer: u8) -> bool {
        if self.owner.is_some() {
            return false;
        }
        self.owner = Some(writer);
        true
    }

    fn publish_intent(
        &mut self,
        expected: Receipt,
        result: Publication,
    ) -> Result<Receipt, Refusal> {
        if self.identity != expected.store || self.owner != Some(expected.writer) {
            return Err(Refusal::Ownership);
        }
        match result {
            Publication::Acknowledged => {
                self.visible_intent = Some(expected);
                Ok(expected)
            }
            Publication::FailedBeforePublication => Err(Refusal::IntentUnacknowledged),
            Publication::VisibleButError => {
                self.visible_intent = Some(expected);
                Err(Refusal::IntentUnacknowledged)
            }
            Publication::Uncertain => Err(Refusal::IntentUnacknowledged),
        }
    }

    fn publish_outcome(&mut self, report: &ApplyReport, result: Publication) {
        if matches!(
            result,
            Publication::Acknowledged | Publication::VisibleButError
        ) {
            self.visible_outcome = Some(report.clone());
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Domain {
    Snapshot,
    Epoch,
    Callback,
    Signing,
    Outbound,
    Storage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SigningStage {
    RequestAdmitted,
    ReservationObserved,
    KeyInvocationObserved,
    SignatureObserved,
}

const DOMAINS: [Domain; 6] = [
    Domain::Snapshot,
    Domain::Epoch,
    Domain::Callback,
    Domain::Signing,
    Domain::Outbound,
    Domain::Storage,
];

#[derive(Clone, Debug)]
struct Work {
    domain: Domain,
    signing_stage: Option<SigningStage>,
    cancellation_requested: bool,
    completion: Observation,
    enqueued: bool,
    peer_delivery: Observation,
    known_effect: bool,
    conflict: bool,
}

impl Work {
    fn accounted_for(&self) -> bool {
        !self.conflict
            && self.completion.resolved()
            && (self.domain != Domain::Outbound || self.peer_delivery.resolved())
    }

    fn summary(&self) -> Observation {
        if self.conflict {
            Observation::Conflict
        } else if !self.accounted_for() {
            if self.known_effect {
                Observation::EffectUnresolved
            } else {
                Observation::Unknown
            }
        } else if self.known_effect {
            Observation::EffectObserved
        } else {
            Observation::NoEffect
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    AlreadyRunningFixture,
    Preparing,
    Applying,
    Latched,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    Gate,
    Barrier,
    IntentUnacknowledged,
    Ownership,
    ExistingId,
    Capacity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Item {
    New(u8),
    FailAfterInsertion(u8),
    UnknownDuringItem,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CurrentItem {
    None,
    Refused { index: usize, reason: Refusal },
    InsertedBeforeFailure { index: usize, id: u8 },
    Unknown { index: usize },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ApplyReport {
    completed_prefix: Vec<u8>,
    current: CurrentItem,
    complete: bool,
}

#[derive(Clone, Copy, Debug)]
enum PassiveEvent {
    EmptyResponse,
    StaleResponse,
    Timeout,
    OperatorAcknowledgement,
    LocalChecksumValid,
    LocalGenerationMatches,
}

// Each field is a separate effect domain; engine-only equality is not a
// blanket no-effect claim. An intent is an intentional storage effect.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Effects {
    engine: Observation,
    signing: Observation,
    durable_record: Observation,
    storage_workers: Observation,
    external: Observation,
    callbacks: Observation,
}

#[derive(Clone, Debug)]
struct Model {
    phase: Phase,
    expected: Receipt,
    intent: Option<Receipt>,
    work: Vec<Work>,
    blocks: BTreeMap<u8, usize>,
    retained_charge: usize,
    capacity: usize,
    report: Option<ApplyReport>,
    outcome_acknowledged: bool,
    effects: Effects,
}

impl Model {
    fn already_running_fixture(store: u8, writer: u8) -> Self {
        Self {
            // Fixture precondition only: no startup or clear authority is modeled.
            phase: Phase::AlreadyRunningFixture,
            expected: Receipt { store, writer },
            intent: None,
            work: Vec::new(),
            blocks: BTreeMap::new(),
            retained_charge: 0,
            capacity: 2,
            report: None,
            outcome_acknowledged: false,
            effects: Effects {
                engine: Observation::NoEffect,
                signing: Observation::NoEffect,
                durable_record: Observation::NoEffect,
                storage_workers: Observation::NoEffect,
                external: Observation::NoEffect,
                callbacks: Observation::NoEffect,
            },
        }
    }

    fn startup(read: MarkerRead, store: u8, writer: u8) -> Self {
        let mut model = Self::already_running_fixture(store, writer);
        match read {
            MarkerRead::Missing
            | MarkerRead::Corrupt
            | MarkerRead::Unsupported
            | MarkerRead::Foreign
            | MarkerRead::StorageAbsent
            | MarkerRead::IoFailure
            | MarkerRead::Uncertain
            | MarkerRead::ParsedClean
            | MarkerRead::ParsedApplying
            | MarkerRead::ParsedComplete => {
                // A parsed local record supplies neither currentness nor
                // exclusive signing evidence. This slice has no clear operation.
                model.phase = Phase::Latched;
            }
        }
        model.effects = Effects {
            engine: Observation::Unknown,
            signing: Observation::Unknown,
            durable_record: Observation::Unknown,
            storage_workers: Observation::Unknown,
            external: Observation::Unknown,
            callbacks: Observation::Unknown,
        };
        model
    }

    fn admit_ordinary(&mut self, domain: Domain) -> Result<usize, Refusal> {
        if self.phase != Phase::AlreadyRunningFixture {
            return Err(Refusal::Gate);
        }
        self.work.push(Work {
            domain,
            signing_stage: (domain == Domain::Signing).then_some(SigningStage::RequestAdmitted),
            cancellation_requested: false,
            completion: Observation::Unknown,
            enqueued: false,
            peer_delivery: Observation::Unknown,
            known_effect: false,
            conflict: false,
        });
        self.refresh_work_observations();
        Ok(self.work.len() - 1)
    }

    fn close_admission(&mut self) -> Result<(), Refusal> {
        if self.phase != Phase::AlreadyRunningFixture {
            return Err(Refusal::Gate);
        }
        self.phase = Phase::Preparing;
        Ok(())
    }

    fn acknowledge_intent(
        &mut self,
        store: &mut MockStore,
        publication: Publication,
    ) -> Result<(), Refusal> {
        if self.phase != Phase::Preparing {
            return Err(Refusal::Gate);
        }
        self.effects.durable_record = if self.intent.is_some() {
            Observation::EffectUnresolved
        } else {
            Observation::Unknown
        };
        match store.publish_intent(self.expected, publication) {
            Ok(receipt) => {
                self.intent = Some(receipt);
                self.effects.durable_record = Observation::EffectObserved;
                Ok(())
            }
            Err(error) => {
                if store.visible_intent == Some(self.expected) {
                    self.effects.durable_record = Observation::EffectUnresolved;
                }
                self.phase = Phase::Latched;
                Err(error)
            }
        }
    }

    fn observe_completion(&mut self, index: usize, observation: Observation) {
        let work = &mut self.work[index];
        work.completion = work.completion.merge_completion(observation);
        work.conflict |= work.completion == Observation::Conflict
            || (observation == Observation::NoEffect && work.known_effect);
        work.known_effect |= observation == Observation::EffectObserved;
        self.refresh_work_observations();
    }

    fn refresh_work_observations(&mut self) {
        let summarize = |domains: &[Domain]| {
            let workers: Vec<_> = self
                .work
                .iter()
                .filter(|work| domains.contains(&work.domain))
                .collect();
            if workers
                .iter()
                .any(|work| work.summary() == Observation::Conflict)
            {
                return Observation::Conflict;
            }
            let known_effect = workers.iter().any(|work| work.known_effect);
            let unresolved = workers.iter().any(|work| !work.accounted_for());
            match (known_effect, unresolved) {
                (true, true) => Observation::EffectUnresolved,
                (true, false) => Observation::EffectObserved,
                (false, true) => Observation::Unknown,
                (false, false) => Observation::NoEffect,
            }
        };
        self.effects.signing = summarize(&[Domain::Signing]);
        self.effects.storage_workers = summarize(&[Domain::Storage]);
        self.effects.callbacks = summarize(&[Domain::Snapshot, Domain::Epoch, Domain::Callback]);
        self.effects.external = summarize(&[Domain::Outbound]);
        if self.work.iter().any(|work| work.conflict) {
            self.phase = Phase::Latched;
        }
    }

    fn observe_signing_stage(&mut self, index: usize, stage: SigningStage) {
        let work = &mut self.work[index];
        assert_eq!(work.domain, Domain::Signing);
        let previous = work.signing_stage.unwrap();
        // Keep the highest observed stage. New stages after a terminal
        // completion or backward stages conflict; exact repeats are harmless.
        work.conflict |=
            stage < previous || (stage != previous && work.completion != Observation::Unknown);
        work.signing_stage = Some(previous.max(stage));
        work.known_effect |= stage > SigningStage::RequestAdmitted;
        work.conflict |= work.known_effect && work.completion == Observation::NoEffect;
        self.refresh_work_observations();
    }

    fn request_cancel(&mut self, index: usize) {
        self.work[index].cancellation_requested = true;
    }

    fn enqueue(&mut self, index: usize) {
        let work = &mut self.work[index];
        assert_eq!(work.domain, Domain::Outbound);
        work.conflict |= !work.enqueued && work.completion != Observation::Unknown;
        work.enqueued = true;
        work.known_effect = true;
        self.refresh_work_observations();
    }

    fn observe_delivery(&mut self, index: usize, observation: Observation) {
        let work = &mut self.work[index];
        assert_eq!(work.domain, Domain::Outbound);
        work.peer_delivery = work.peer_delivery.merge_completion(observation);
        work.known_effect |= observation == Observation::EffectObserved;
        work.conflict |= work.peer_delivery == Observation::Conflict
            || (work.known_effect && work.completion == Observation::NoEffect);
        self.refresh_work_observations();
    }

    fn mutation_gate(&self, store: &MockStore) -> Result<(), Refusal> {
        if self.phase != Phase::Preparing {
            return Err(Refusal::Gate);
        }
        if self.intent != Some(self.expected) {
            return Err(Refusal::IntentUnacknowledged);
        }
        if store.identity != self.expected.store
            || store.owner != Some(self.expected.writer)
            || store.visible_intent != Some(self.expected)
        {
            return Err(Refusal::Ownership);
        }
        if self.work.iter().any(|work| !work.accounted_for()) {
            return Err(Refusal::Barrier);
        }
        Ok(())
    }

    fn apply(
        &mut self,
        store: &mut MockStore,
        items: &[Item],
        outcome: Publication,
    ) -> Result<ApplyReport, Refusal> {
        if let Err(error) = self.mutation_gate(store) {
            self.phase = Phase::Latched;
            return Err(error);
        }
        self.phase = Phase::Applying;
        let mut report = ApplyReport {
            completed_prefix: Vec::new(),
            current: CurrentItem::None,
            complete: true,
        };
        for (index, item) in items.iter().enumerate() {
            if *item == Item::UnknownDuringItem {
                self.effects.engine = if report.completed_prefix.is_empty() {
                    Observation::Unknown
                } else {
                    Observation::EffectUnresolved
                };
                report.current = CurrentItem::Unknown { index };
                report.complete = false;
                break;
            }
            let id = match item {
                Item::New(id) | Item::FailAfterInsertion(id) => *id,
                Item::UnknownDuringItem => unreachable!(),
            };
            let refusal = if self.blocks.contains_key(&id) {
                Some(Refusal::ExistingId)
            } else if self.blocks.len() >= self.capacity {
                // All resident fixture blocks are protected. No eviction or
                // real ancestry/consensus implementation is modeled here.
                Some(Refusal::Capacity)
            } else {
                None
            };
            if let Some(reason) = refusal {
                report.current = CurrentItem::Refused { index, reason };
                report.complete = false;
                break;
            }
            self.blocks.insert(id, 1);
            self.retained_charge += 1;
            self.effects.engine = Observation::EffectObserved;
            if matches!(item, Item::FailAfterInsertion(_)) {
                report.current = CurrentItem::InsertedBeforeFailure { index, id };
                report.complete = false;
                break;
            }
            report.completed_prefix.push(id);
        }
        // Even Complete/no-effect refusal and acknowledged outcome stay closed.
        self.phase = Phase::Latched;
        self.report = Some(report.clone());
        // The acknowledged intent remains a known storage effect even when
        // publication/completion of the outcome is uncertain.
        self.effects.durable_record = Observation::EffectUnresolved;
        store.publish_outcome(&report, outcome);
        self.outcome_acknowledged = outcome == Publication::Acknowledged;
        if self.outcome_acknowledged {
            self.effects.durable_record = Observation::EffectObserved;
        }
        Ok(report)
    }

    fn passive_event(&mut self, _event: PassiveEvent) {
        // No clear transition is present in the reviewed stay-closed slice.
    }
}

fn prepared() -> (Model, MockStore) {
    let mut store = MockStore::new(1);
    assert!(store.claim(7));
    let mut model = Model::already_running_fixture(1, 7);
    model.close_admission().unwrap();
    model
        .acknowledge_intent(&mut store, Publication::Acknowledged)
        .unwrap();
    (model, store)
}

fn assert_closed(model: &mut Model) {
    for domain in DOMAINS {
        let before = model.work.len();
        assert_eq!(model.admit_ordinary(domain), Err(Refusal::Gate));
        assert_eq!(model.work.len(), before);
    }
}

#[test]
fn all_unproven_startup_observations_refuse_participation() {
    for read in [
        MarkerRead::Missing,
        MarkerRead::Corrupt,
        MarkerRead::Unsupported,
        MarkerRead::Foreign,
        MarkerRead::StorageAbsent,
        MarkerRead::IoFailure,
        MarkerRead::Uncertain,
        MarkerRead::ParsedClean,
        MarkerRead::ParsedApplying,
        MarkerRead::ParsedComplete,
    ] {
        let mut model = Model::startup(read, 1, 7);
        assert_closed(&mut model);
        let mut store = MockStore::new(1);
        assert!(store.claim(7));
        assert_eq!(
            model.apply(&mut store, &[Item::New(1)], Publication::Acknowledged),
            Err(Refusal::Gate)
        );
        assert!(model.blocks.is_empty());
        assert_eq!(model.effects.signing, Observation::Unknown);
    }
}

#[test]
fn acknowledged_intent_and_closed_barrier_allow_fixture_mutation_only() {
    let (mut model, mut store) = prepared();
    assert_eq!(model.mutation_gate(&store), Ok(()));
    assert_closed(&mut model);
    let report = model
        .apply(&mut store, &[Item::New(1)], Publication::Acknowledged)
        .unwrap();
    assert!(report.complete);
    assert_eq!(report.completed_prefix, vec![1]);
    assert_eq!(model.blocks.len(), 1);
    assert_eq!(model.retained_charge, 1);
    assert!(model.outcome_acknowledged);
    assert_closed(&mut model);
}

#[test]
fn mutation_without_acknowledged_intent_is_refused() {
    let mut model = Model::already_running_fixture(1, 7);
    let mut store = MockStore::new(1);
    assert!(store.claim(7));
    model.close_admission().unwrap();
    assert_eq!(
        model.apply(&mut store, &[Item::New(1)], Publication::Acknowledged),
        Err(Refusal::IntentUnacknowledged)
    );
    assert!(model.blocks.is_empty());
    assert_eq!(model.retained_charge, 0);
    assert_closed(&mut model);
}

#[test]
fn open_admission_is_not_an_operation_barrier() {
    let mut model = Model::already_running_fixture(1, 7);
    let mut store = MockStore::new(1);
    assert!(store.claim(7));
    assert_eq!(
        model.acknowledge_intent(&mut store, Publication::Acknowledged),
        Err(Refusal::Gate)
    );
    assert_eq!(
        model.apply(&mut store, &[Item::New(1)], Publication::Acknowledged),
        Err(Refusal::Gate)
    );
    assert!(store.visible_intent.is_none());
    assert!(model.blocks.is_empty());
}

#[test]
fn failed_uncertain_and_visible_but_error_intents_stay_unresolved() {
    for result in [
        Publication::FailedBeforePublication,
        Publication::VisibleButError,
        Publication::Uncertain,
    ] {
        let mut model = Model::already_running_fixture(1, 7);
        let mut store = MockStore::new(1);
        assert!(store.claim(7));
        model.close_admission().unwrap();
        assert_eq!(
            model.acknowledge_intent(&mut store, result),
            Err(Refusal::IntentUnacknowledged)
        );
        assert_eq!(
            store.visible_intent.is_some(),
            result == Publication::VisibleButError
        );
        assert_eq!(model.intent, None);
        assert_eq!(
            model.effects.durable_record,
            if result == Publication::VisibleButError {
                Observation::EffectUnresolved
            } else {
                Observation::Unknown
            }
        );
        assert_eq!(
            model.apply(&mut store, &[Item::New(1)], Publication::Acknowledged),
            Err(Refusal::Gate)
        );
        assert!(model.blocks.is_empty());
        assert_closed(&mut model);
    }
}

#[test]
fn cancellation_request_does_not_observe_completion_in_any_domain() {
    for domain in DOMAINS {
        let mut model = Model::already_running_fixture(1, 7);
        let work = model.admit_ordinary(domain).unwrap();
        model.request_cancel(work);
        model.close_admission().unwrap();
        let mut store = MockStore::new(1);
        assert!(store.claim(7));
        model
            .acknowledge_intent(&mut store, Publication::Acknowledged)
            .unwrap();
        assert!(model.work[work].cancellation_requested);
        assert_eq!(
            model.apply(&mut store, &[Item::New(1)], Publication::Acknowledged),
            Err(Refusal::Barrier)
        );
        assert!(model.blocks.is_empty());
        model.observe_completion(work, Observation::EffectObserved);
        if domain == Domain::Outbound {
            model.observe_delivery(work, Observation::EffectObserved);
        }
        // Late observed completion cannot clear a previously latched failure.
        assert_closed(&mut model);
        assert_eq!(model.mutation_gate(&store), Err(Refusal::Gate));
    }
}

#[test]
fn observed_preexisting_work_can_satisfy_barrier_without_retracting_effects() {
    let mut model = Model::already_running_fixture(1, 7);
    let signer = model.admit_ordinary(Domain::Signing).unwrap();
    model.close_admission().unwrap();
    model.observe_completion(signer, Observation::EffectObserved);
    let mut store = MockStore::new(1);
    assert!(store.claim(7));
    model
        .acknowledge_intent(&mut store, Publication::Acknowledged)
        .unwrap();
    model
        .apply(&mut store, &[Item::New(1)], Publication::Acknowledged)
        .unwrap();
    assert_eq!(model.effects.signing, Observation::EffectObserved);
    assert_closed(&mut model);
}

#[test]
fn enqueue_and_worker_completion_are_not_peer_delivery() {
    let mut model = Model::already_running_fixture(1, 7);
    let outbound = model.admit_ordinary(Domain::Outbound).unwrap();
    model.enqueue(outbound);
    model.close_admission().unwrap();
    let mut store = MockStore::new(1);
    assert!(store.claim(7));
    model
        .acknowledge_intent(&mut store, Publication::Acknowledged)
        .unwrap();
    assert!(model.work[outbound].enqueued);
    assert_eq!(model.mutation_gate(&store), Err(Refusal::Barrier));
    model.observe_completion(outbound, Observation::EffectObserved);
    assert_eq!(model.work[outbound].peer_delivery, Observation::Unknown);
    assert_eq!(model.mutation_gate(&store), Err(Refusal::Barrier));
    model.observe_delivery(outbound, Observation::EffectObserved);
    assert_eq!(model.mutation_gate(&store), Ok(()));
    assert_eq!(model.effects.external, Observation::EffectObserved);
}

#[test]
fn valid_prefix_then_capacity_refusal_retains_and_reports_prefix() {
    let (mut model, mut store) = prepared();
    model.capacity = 1;
    let report = model
        .apply(
            &mut store,
            &[Item::New(10), Item::New(11)],
            Publication::Acknowledged,
        )
        .unwrap();
    assert_eq!(report.completed_prefix, vec![10]);
    assert_eq!(
        report.current,
        CurrentItem::Refused {
            index: 1,
            reason: Refusal::Capacity
        }
    );
    assert!(!report.complete);
    assert_eq!(model.blocks, BTreeMap::from([(10, 1)]));
    assert_eq!(model.retained_charge, 1);
    assert_closed(&mut model);
}

#[test]
fn existing_id_refusal_preserves_charge_and_has_no_current_item_effects() {
    let (mut model, mut store) = prepared();
    model.blocks.insert(10, 3);
    model.retained_charge = 3;
    let before = model.blocks.clone();
    let report = model
        .apply(&mut store, &[Item::New(10)], Publication::Acknowledged)
        .unwrap();
    assert!(report.completed_prefix.is_empty());
    assert_eq!(
        report.current,
        CurrentItem::Refused {
            index: 0,
            reason: Refusal::ExistingId
        }
    );
    assert_eq!(model.blocks, before);
    assert_eq!(model.retained_charge, 3);
    assert_eq!(model.effects.engine, Observation::NoEffect);
    assert_eq!(model.effects.durable_record, Observation::EffectObserved);
    assert_closed(&mut model);
}

#[test]
fn repeated_id_in_response_reports_prefix_without_replacement() {
    let (mut model, mut store) = prepared();
    let report = model
        .apply(
            &mut store,
            &[Item::New(10), Item::New(10)],
            Publication::Acknowledged,
        )
        .unwrap();
    assert_eq!(report.completed_prefix, vec![10]);
    assert_eq!(
        report.current,
        CurrentItem::Refused {
            index: 1,
            reason: Refusal::ExistingId
        }
    );
    assert_eq!(model.retained_charge, 1);
    assert_closed(&mut model);
}

#[test]
fn prefix_and_observed_current_item_effects_are_separate() {
    let (mut model, mut store) = prepared();
    let report = model
        .apply(
            &mut store,
            &[Item::New(10), Item::FailAfterInsertion(11)],
            Publication::Acknowledged,
        )
        .unwrap();
    assert_eq!(report.completed_prefix, vec![10]);
    assert_eq!(
        report.current,
        CurrentItem::InsertedBeforeFailure { index: 1, id: 11 }
    );
    assert_eq!(model.blocks, BTreeMap::from([(10, 1), (11, 1)]));
    assert_eq!(model.retained_charge, 2);
    assert_closed(&mut model);
}

#[test]
fn unknown_current_item_effects_never_erase_known_prefix() {
    let (mut model, mut store) = prepared();
    let report = model
        .apply(
            &mut store,
            &[Item::New(10), Item::UnknownDuringItem],
            Publication::Acknowledged,
        )
        .unwrap();
    assert_eq!(report.completed_prefix, vec![10]);
    assert_eq!(report.current, CurrentItem::Unknown { index: 1 });
    assert_eq!(model.effects.engine, Observation::EffectUnresolved);
    assert_eq!(model.blocks.get(&10), Some(&1));
    assert_closed(&mut model);
}

#[test]
fn failed_and_uncertain_outcomes_keep_effects_and_never_clear() {
    for outcome in [
        Publication::FailedBeforePublication,
        Publication::VisibleButError,
        Publication::Uncertain,
    ] {
        let (mut model, mut store) = prepared();
        let report = model.apply(&mut store, &[Item::New(1)], outcome).unwrap();
        assert!(report.complete);
        assert_eq!(model.report.as_ref(), Some(&report));
        assert_eq!(
            store.visible_outcome.as_ref(),
            if outcome == Publication::VisibleButError {
                Some(&report)
            } else {
                None
            }
        );
        assert!(!model.outcome_acknowledged);
        assert_eq!(model.effects.durable_record, Observation::EffectUnresolved);
        assert_eq!(model.blocks.len(), 1);
        assert_closed(&mut model);
    }
}

#[test]
fn complete_empty_and_no_effect_results_have_no_automatic_clear() {
    for (capacity, items) in [
        (2, vec![Item::New(1)]),
        (2, vec![]),
        (0, vec![Item::New(1)]),
    ] {
        let (mut model, mut store) = prepared();
        model.capacity = capacity;
        model
            .apply(&mut store, &items, Publication::Acknowledged)
            .unwrap();
        for event in [
            PassiveEvent::EmptyResponse,
            PassiveEvent::StaleResponse,
            PassiveEvent::Timeout,
            PassiveEvent::OperatorAcknowledgement,
            PassiveEvent::LocalChecksumValid,
            PassiveEvent::LocalGenerationMatches,
        ] {
            model.passive_event(event);
            assert_closed(&mut model);
            assert_eq!(model.close_admission(), Err(Refusal::Gate));
        }
        assert_eq!(
            model.apply(&mut store, &items, Publication::Acknowledged),
            Err(Refusal::Gate)
        );
    }
}

#[test]
fn modeled_restart_and_stale_valid_copies_cannot_authorize_participation() {
    let (mut original, mut store) = prepared();
    original
        .apply(&mut store, &[Item::New(1)], Publication::Acknowledged)
        .unwrap();
    for read in [
        MarkerRead::ParsedClean,
        MarkerRead::ParsedApplying,
        MarkerRead::ParsedComplete,
    ] {
        // Both identical stores are local fixture copies, not a fencing proof.
        let copy = store.clone();
        for _local_store in [&store, &copy] {
            let mut restarted = Model::startup(read, 1, 7);
            restarted.passive_event(PassiveEvent::LocalGenerationMatches);
            restarted.passive_event(PassiveEvent::LocalChecksumValid);
            assert_closed(&mut restarted);
            assert_eq!(restarted.effects.signing, Observation::Unknown);
        }
    }
}

#[test]
fn deterministic_concurrent_writer_claim_refuses_second_writer() {
    for (first, second) in [(7, 8), (8, 7)] {
        let mut store = MockStore::new(1);
        assert!(store.claim(first));
        assert!(!store.claim(second));
        let mut rejected = Model::already_running_fixture(1, second);
        rejected.close_admission().unwrap();
        assert_eq!(
            rejected.acknowledge_intent(&mut store, Publication::Acknowledged),
            Err(Refusal::Ownership)
        );
        assert!(store.visible_intent.is_none());
        assert_closed(&mut rejected);
    }
}

#[test]
fn changed_store_identity_or_owner_invalidates_receipt_before_mutation() {
    for change_identity in [true, false] {
        let (mut model, mut store) = prepared();
        if change_identity {
            store.identity = 2;
        } else {
            store.owner = Some(8);
        }
        assert_eq!(
            model.apply(&mut store, &[Item::New(1)], Publication::Acknowledged),
            Err(Refusal::Ownership)
        );
        assert!(model.blocks.is_empty());
        assert_closed(&mut model);
    }
}

#[test]
fn foreign_store_intent_is_not_accepted_even_when_writer_matches() {
    let mut model = Model::already_running_fixture(1, 7);
    let mut store = MockStore::new(2);
    assert!(store.claim(7));
    model.close_admission().unwrap();
    assert_eq!(
        model.acknowledge_intent(&mut store, Publication::Acknowledged),
        Err(Refusal::Ownership)
    );
    assert!(store.visible_intent.is_none());
    assert_closed(&mut model);
}

#[test]
fn reservation_key_invocation_and_signature_do_not_replace_worker_completion() {
    for stage in [
        SigningStage::RequestAdmitted,
        SigningStage::ReservationObserved,
        SigningStage::KeyInvocationObserved,
        SigningStage::SignatureObserved,
    ] {
        let mut model = Model::already_running_fixture(1, 7);
        let request = model.admit_ordinary(Domain::Signing).unwrap();
        model.observe_signing_stage(request, stage);
        model.close_admission().unwrap();
        let mut store = MockStore::new(1);
        assert!(store.claim(7));
        model
            .acknowledge_intent(&mut store, Publication::Acknowledged)
            .unwrap();
        assert_eq!(model.work[request].signing_stage, Some(stage));
        assert_eq!(model.work[request].completion, Observation::Unknown);
        assert_eq!(
            model.effects.signing,
            if stage == SigningStage::RequestAdmitted {
                Observation::Unknown
            } else {
                Observation::EffectUnresolved
            }
        );
        assert_eq!(
            model.apply(&mut store, &[Item::New(1)], Publication::Acknowledged),
            Err(Refusal::Barrier)
        );
        model.request_cancel(request);
        model.observe_completion(request, Observation::EffectObserved);
        assert_eq!(model.effects.signing, Observation::EffectObserved);
        assert_closed(&mut model);
        assert!(model.blocks.is_empty());
    }
}

#[test]
fn one_completed_worker_does_not_hide_another_unknown_worker() {
    for domain in [Domain::Signing, Domain::Storage, Domain::Callback] {
        let mut model = Model::already_running_fixture(1, 7);
        let first = model.admit_ordinary(domain).unwrap();
        let second = model.admit_ordinary(domain).unwrap();
        model.observe_completion(first, Observation::NoEffect);
        model.close_admission().unwrap();
        let mut store = MockStore::new(1);
        assert!(store.claim(7));
        model
            .acknowledge_intent(&mut store, Publication::Acknowledged)
            .unwrap();
        let observation = match domain {
            Domain::Signing => model.effects.signing,
            Domain::Storage => model.effects.storage_workers,
            Domain::Callback => model.effects.callbacks,
            _ => unreachable!(),
        };
        assert_eq!(observation, Observation::Unknown);
        assert_eq!(model.mutation_gate(&store), Err(Refusal::Barrier));
        model.observe_completion(second, Observation::NoEffect);
        assert_eq!(model.mutation_gate(&store), Ok(()));
    }
}

#[test]
fn repeated_response_after_partial_application_cannot_reenter_catchup() {
    let (mut model, mut store) = prepared();
    model.capacity = 1;
    let items = [Item::New(10), Item::New(11)];
    let first = model
        .apply(&mut store, &items, Publication::Acknowledged)
        .unwrap();
    let before = model.blocks.clone();
    assert_eq!(
        model.apply(&mut store, &items, Publication::Acknowledged),
        Err(Refusal::Gate)
    );
    assert_eq!(model.report.as_ref(), Some(&first));
    assert_eq!(model.blocks, before);
    assert_eq!(model.retained_charge, 1);
    assert_closed(&mut model);
}

#[test]
fn local_writer_serialization_does_not_prove_exclusivity_across_copies() {
    let mut store = MockStore::new(1);
    assert!(store.claim(7));
    let mut copy = store.clone();
    let receipt = Receipt {
        store: 1,
        writer: 7,
    };
    // Both copied fixture stores accept their local writer. This deliberately
    // demonstrates why local serialization is not an identity-fencing proof.
    assert_eq!(
        store.publish_intent(receipt, Publication::Acknowledged),
        Ok(receipt)
    );
    assert_eq!(
        copy.publish_intent(receipt, Publication::Acknowledged),
        Ok(receipt)
    );
    for local in [store, copy] {
        assert_eq!(local.visible_intent, Some(receipt));
        let mut restarted = Model::startup(MarkerRead::ParsedApplying, 1, 7);
        assert_closed(&mut restarted);
    }
}

#[test]
fn signature_then_no_effect_completion_cannot_claim_no_effect() {
    let mut model = Model::already_running_fixture(1, 7);
    let worker = model.admit_ordinary(Domain::Signing).unwrap();
    model.observe_signing_stage(worker, SigningStage::SignatureObserved);
    model.observe_completion(worker, Observation::NoEffect);
    assert_eq!(model.effects.signing, Observation::Conflict);
    assert!(model.work[worker].known_effect);
    assert_eq!(
        model.work[worker].signing_stage,
        Some(SigningStage::SignatureObserved)
    );
    assert!(!model.work[worker].accounted_for());
    assert_closed(&mut model);
}

#[test]
fn reservation_and_key_effects_survive_contradictory_late_completion() {
    for stage in [
        SigningStage::ReservationObserved,
        SigningStage::KeyInvocationObserved,
    ] {
        let mut model = Model::already_running_fixture(1, 7);
        let worker = model.admit_ordinary(Domain::Signing).unwrap();
        model.observe_signing_stage(worker, stage);
        model.close_admission().unwrap();
        let mut store = MockStore::new(1);
        assert!(store.claim(7));
        model
            .acknowledge_intent(&mut store, Publication::Acknowledged)
            .unwrap();
        assert_eq!(
            model.apply(&mut store, &[Item::New(1)], Publication::Acknowledged),
            Err(Refusal::Barrier)
        );
        for completion in [
            Observation::NoEffect,
            Observation::EffectObserved,
            Observation::Unknown,
        ] {
            model.observe_completion(worker, completion);
            assert!(model.work[worker].known_effect);
            assert_eq!(model.effects.signing, Observation::Conflict);
            assert!(!model.work[worker].accounted_for());
            assert_closed(&mut model);
        }
    }
}

#[test]
fn backward_signing_stages_preserve_highest_stage_and_latch_conflict() {
    let mut model = Model::already_running_fixture(1, 7);
    let worker = model.admit_ordinary(Domain::Signing).unwrap();
    model.observe_signing_stage(worker, SigningStage::SignatureObserved);
    model.observe_signing_stage(worker, SigningStage::SignatureObserved);
    assert_eq!(model.effects.signing, Observation::EffectUnresolved);
    for stage in [
        SigningStage::KeyInvocationObserved,
        SigningStage::RequestAdmitted,
        SigningStage::SignatureObserved,
    ] {
        model.observe_signing_stage(worker, stage);
        model.observe_completion(worker, Observation::EffectObserved);
        assert_eq!(
            model.work[worker].signing_stage,
            Some(SigningStage::SignatureObserved)
        );
        assert_eq!(model.effects.signing, Observation::Conflict);
        assert!(model.work[worker].known_effect);
        assert_closed(&mut model);
    }
}

#[test]
fn every_worker_domain_keeps_effects_when_completion_is_repeated_or_reversed() {
    for domain in DOMAINS {
        let mut model = Model::already_running_fixture(1, 7);
        let worker = model.admit_ordinary(domain).unwrap();
        model.observe_completion(worker, Observation::EffectObserved);
        model.observe_completion(worker, Observation::EffectObserved);
        assert!(model.work[worker].known_effect);
        assert!(!model.work[worker].conflict);
        model.observe_completion(worker, Observation::NoEffect);
        model.observe_completion(worker, Observation::EffectObserved);
        model.observe_completion(worker, Observation::Unknown);
        assert!(model.work[worker].known_effect);
        assert_eq!(model.work[worker].summary(), Observation::Conflict);
        assert!(!model.work[worker].accounted_for());
        assert_closed(&mut model);
    }
}

#[test]
fn terminal_completion_followed_by_unknown_is_not_a_new_no_effect_proof() {
    for completion in [Observation::NoEffect, Observation::EffectObserved] {
        let mut model = Model::already_running_fixture(1, 7);
        let worker = model.admit_ordinary(Domain::Callback).unwrap();
        model.observe_completion(worker, completion);
        model.observe_completion(worker, Observation::Unknown);
        assert_eq!(model.effects.callbacks, Observation::Conflict);
        assert!(!model.work[worker].accounted_for());
        assert_closed(&mut model);
    }
}

#[test]
fn late_stage_after_completion_cannot_rewrite_the_completed_history() {
    for completion in [Observation::NoEffect, Observation::EffectObserved] {
        let mut model = Model::already_running_fixture(1, 7);
        let worker = model.admit_ordinary(Domain::Signing).unwrap();
        model.observe_completion(worker, completion);
        model.observe_signing_stage(worker, SigningStage::ReservationObserved);
        assert_eq!(model.effects.signing, Observation::Conflict);
        assert!(model.work[worker].known_effect);
        assert!(!model.work[worker].accounted_for());
        assert_closed(&mut model);
    }
}

#[test]
fn known_effect_and_unknown_worker_are_reported_together_in_either_order() {
    for domain in DOMAINS {
        for known_first in [false, true] {
            let mut model = Model::already_running_fixture(1, 7);
            let first = model.admit_ordinary(domain).unwrap();
            let second = model.admit_ordinary(domain).unwrap();
            let (known, unknown) = if known_first {
                (first, second)
            } else {
                (second, first)
            };
            model.observe_completion(known, Observation::EffectObserved);
            if domain == Domain::Outbound {
                model.observe_delivery(known, Observation::EffectObserved);
            }
            model.refresh_work_observations();
            let summary = match domain {
                Domain::Signing => model.effects.signing,
                Domain::Outbound => model.effects.external,
                Domain::Storage => model.effects.storage_workers,
                _ => model.effects.callbacks,
            };
            assert_eq!(summary, Observation::EffectUnresolved);
            assert!(model.work[known].known_effect);
            assert_eq!(model.work[unknown].completion, Observation::Unknown);
            model.close_admission().unwrap();
            let mut store = MockStore::new(1);
            assert!(store.claim(7));
            model
                .acknowledge_intent(&mut store, Publication::Acknowledged)
                .unwrap();
            assert_eq!(model.mutation_gate(&store), Err(Refusal::Barrier));
        }
    }
}

#[test]
fn enqueue_and_delivery_effects_survive_contradictory_updates() {
    let mut model = Model::already_running_fixture(1, 7);
    let worker = model.admit_ordinary(Domain::Outbound).unwrap();
    model.enqueue(worker);
    model.enqueue(worker);
    assert_eq!(model.effects.external, Observation::EffectUnresolved);
    model.observe_completion(worker, Observation::NoEffect);
    assert_eq!(model.effects.external, Observation::Conflict);
    assert!(model.work[worker].enqueued);
    assert!(model.work[worker].known_effect);
    model.observe_completion(worker, Observation::EffectObserved);
    model.observe_delivery(worker, Observation::EffectObserved);
    model.observe_delivery(worker, Observation::NoEffect);
    assert_eq!(model.work[worker].peer_delivery, Observation::Conflict);
    assert_eq!(model.effects.external, Observation::Conflict);
    assert_closed(&mut model);
}

#[test]
fn consistent_signing_sequence_and_repeated_observations_still_stay_closed() {
    let mut model = Model::already_running_fixture(1, 7);
    let worker = model.admit_ordinary(Domain::Signing).unwrap();
    for stage in [
        SigningStage::ReservationObserved,
        SigningStage::KeyInvocationObserved,
        SigningStage::SignatureObserved,
    ] {
        model.observe_signing_stage(worker, stage);
        model.observe_signing_stage(worker, stage);
        assert_eq!(model.effects.signing, Observation::EffectUnresolved);
    }
    model.observe_completion(worker, Observation::EffectObserved);
    model.observe_completion(worker, Observation::EffectObserved);
    model.observe_signing_stage(worker, SigningStage::SignatureObserved);
    assert!(model.work[worker].accounted_for());
    assert_eq!(model.effects.signing, Observation::EffectObserved);
    model.close_admission().unwrap();
    let mut store = MockStore::new(1);
    assert!(store.claim(7));
    model
        .acknowledge_intent(&mut store, Publication::Acknowledged)
        .unwrap();
    assert_eq!(model.mutation_gate(&store), Ok(()));
    model
        .apply(&mut store, &[Item::New(1)], Publication::Acknowledged)
        .unwrap();
    assert_eq!(model.effects.signing, Observation::EffectObserved);
    assert_closed(&mut model);
}

#[test]
fn enqueue_after_completion_and_reversed_delivery_cannot_erase_effects() {
    let mut model = Model::already_running_fixture(1, 7);
    let worker = model.admit_ordinary(Domain::Outbound).unwrap();
    model.observe_completion(worker, Observation::NoEffect);
    model.observe_delivery(worker, Observation::NoEffect);
    assert_eq!(model.effects.external, Observation::NoEffect);
    model.enqueue(worker);
    assert!(model.work[worker].known_effect);
    assert_eq!(model.effects.external, Observation::Conflict);
    assert_closed(&mut model);

    let mut model = Model::already_running_fixture(1, 7);
    let worker = model.admit_ordinary(Domain::Outbound).unwrap();
    model.observe_delivery(worker, Observation::EffectObserved);
    model.observe_delivery(worker, Observation::NoEffect);
    model.observe_delivery(worker, Observation::EffectObserved);
    assert!(model.work[worker].known_effect);
    assert_eq!(model.work[worker].peer_delivery, Observation::Conflict);
    assert_eq!(model.effects.external, Observation::Conflict);
    assert_closed(&mut model);
}
