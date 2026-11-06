//! Isolated owner/lease lifecycle model for A33-F1 / E27.
//! Mock publication, cancellation, supervision, completion, and restart only;
//! this file does not call production node, engine, storage, signer, or network code.

use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Owner {
    Coordinator,
    Initiator,
    Supervisor,
    Lost,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Domain {
    Signer,
    Storage,
    Snapshot,
    Callback,
    Outbound,
}

const EXTERNAL_DOMAINS: [Domain; 5] = [
    Domain::Signer,
    Domain::Storage,
    Domain::Snapshot,
    Domain::Callback,
    Domain::Outbound,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Visibility {
    NotVisible,
    Visible,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Effect {
    NoEffect,
    EffectObserved,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AnchorTuple {
    committed_id: [u8; 32],
    committed_height: u64,
    current_view: u64,
    lock: Option<([u8; 32], u64)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    AcquireInitiatorLease,
    SnapshotCaptured(AnchorTuple),
    PublishStarted,
    PublishVisible,
    PublishAcknowledged,
    PublishFailed(Visibility),
    InitiatorCancelled,
    SupervisorHandoffOffered,
    SupervisorAcceptedHandoff,
    LeaseDropped(Owner),
    SupervisorLost,
    InterveningMutation(AnchorTuple),
    TupleRevalidated(AnchorTuple),
    ProtectedMutation(Owner),
    ExternalOwnerAccepted(Domain),
    ExternalDomainFenced(Domain),
    ExternalOwnerLost(Domain),
    OperationAdmitted(Domain, u64),
    Completion(Domain, u64, Effect),
    TaskCompleted,
    OrdinaryCleanup,
    ModeledRestart,
    ReopenParticipation,
    ClearUnresolved(Domain, u64),
}

#[derive(Default)]
struct LifecycleModel {
    trace: Vec<Event>,
}

impl LifecycleModel {
    fn record(&mut self, event: Event) {
        self.trace.push(event);
    }

    fn validate(&self) -> Result<(), &'static str> {
        trace_is_valid(&self.trace)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DomainOwner {
    Unknown,
    Accepted,
    Fenced,
    Lost,
}

fn trace_is_valid(trace: &[Event]) -> Result<(), &'static str> {
    let mut owner = Owner::Coordinator;
    let mut engine_lease = false;
    let mut handoff_offered = false;
    let mut cancelled = false;
    let mut publication_started = false;
    let mut publication_visible = false;
    let mut publication_acknowledged = false;
    let mut publication_uncertain = false;
    let mut snapshot = None;
    let mut lease_invalidated = false;
    let mut lifecycle_finished = false;
    let mut restart_seen = false;
    let mut publication_failed = false;

    let mut domain_owners = EXTERNAL_DOMAINS
        .into_iter()
        .map(|domain| (domain, DomainOwner::Unknown))
        .collect::<BTreeMap<_, _>>();
    let mut next_admission = BTreeMap::<Domain, u64>::new();
    let mut next_completion = BTreeMap::<Domain, u64>::new();
    let mut pending = BTreeSet::<(Domain, u64)>::new();
    let mut unresolved = BTreeSet::<(Domain, u64)>::new();
    let mut known_effects = BTreeSet::<(Domain, u64, Effect)>::new();
    let mut conflicts = BTreeSet::<(Domain, u64)>::new();

    for event in trace {
        match *event {
            Event::AcquireInitiatorLease => {
                if owner != Owner::Coordinator || cancelled || lifecycle_finished || restart_seen {
                    return Err("initiator acquired admission outside coordinator handoff");
                }
                owner = Owner::Initiator;
                engine_lease = true;
            }
            Event::SnapshotCaptured(tuple) => {
                if owner != Owner::Initiator || !engine_lease || cancelled {
                    return Err("snapshot captured without initiator engine lease");
                }
                snapshot = Some(tuple);
            }
            Event::PublishStarted => {
                if owner != Owner::Initiator || !engine_lease || snapshot.is_none() || cancelled {
                    return Err("publication started without owned snapshot and lease");
                }
                publication_started = true;
            }
            Event::PublishVisible => {
                if !publication_started
                    || !matches!(owner, Owner::Initiator | Owner::Supervisor)
                    || !engine_lease
                {
                    return Err("publication visibility observed without active publisher");
                }
                publication_visible = true;
            }
            Event::PublishAcknowledged => {
                if !publication_visible
                    || publication_uncertain
                    || publication_failed
                    || !engine_lease
                {
                    return Err("publication acknowledged without certain visible intent");
                }
                publication_acknowledged = true;
            }
            Event::PublishFailed(visibility) => {
                if !publication_started
                    || !matches!(owner, Owner::Initiator | Owner::Supervisor)
                    || !engine_lease
                {
                    return Err("publication failed before publication was started");
                }
                publication_uncertain |= visibility != Visibility::NotVisible;
                publication_failed = true;
                if visibility == Visibility::Visible {
                    publication_visible = true;
                }
                publication_acknowledged = false;
            }
            Event::InitiatorCancelled => {
                if owner == Owner::Initiator {
                    cancelled = true;
                    owner = Owner::Lost;
                    engine_lease = false;
                } else if owner == Owner::Coordinator {
                    cancelled = true;
                }
                unresolved.extend(pending.iter().copied());
            }
            Event::SupervisorHandoffOffered => {
                if owner != Owner::Initiator || !engine_lease || cancelled {
                    return Err("handoff offered without initiator ownership");
                }
                handoff_offered = true;
            }
            Event::SupervisorAcceptedHandoff => {
                if owner != Owner::Initiator || !engine_lease || !handoff_offered || cancelled {
                    return Err("supervisor ownership transferred before acceptance");
                }
                owner = Owner::Supervisor;
                handoff_offered = false;
            }
            Event::LeaseDropped(dropping_owner) => {
                if dropping_owner != owner || !engine_lease {
                    return Err("lease drop does not match active owner");
                }
                owner = Owner::Lost;
                engine_lease = false;
                unresolved.extend(pending.iter().copied());
            }
            Event::SupervisorLost => {
                if owner != Owner::Supervisor {
                    return Err("supervisor loss reported without supervisor ownership");
                }
                owner = Owner::Lost;
                engine_lease = false;
                unresolved.extend(pending.iter().copied());
            }
            Event::InterveningMutation(_) => {
                if engine_lease {
                    lease_invalidated = true;
                    owner = Owner::Lost;
                    engine_lease = false;
                    unresolved.extend(pending.iter().copied());
                }
            }
            Event::TupleRevalidated(tuple) => {
                if lease_invalidated {
                    return Err("tuple equality cannot restore a lost or invalidated lease");
                }
                if snapshot != Some(tuple) {
                    return Err("tuple revalidation detected changed state");
                }
                if !engine_lease || !matches!(owner, Owner::Initiator | Owner::Supervisor) {
                    return Err("tuple revalidated without continuous exclusive ownership");
                }
            }
            Event::ProtectedMutation(mutation_owner) => {
                if mutation_owner != owner
                    || !engine_lease
                    || !matches!(owner, Owner::Initiator | Owner::Supervisor)
                    || !publication_acknowledged
                    || publication_uncertain
                    || cancelled
                    || lease_invalidated
                    || lifecycle_finished
                    || domain_owners
                        .values()
                        .any(|domain_owner| *domain_owner != DomainOwner::Fenced)
                    || !unresolved.is_empty()
                {
                    return Err(
                        "protected mutation lacks acknowledged intent and live owner lease",
                    );
                }
            }
            Event::ExternalOwnerAccepted(domain) => {
                if domain_owners.get(&domain) != Some(&DomainOwner::Unknown) {
                    return Err("external domain owner accepted more than once");
                }
                domain_owners.insert(domain, DomainOwner::Accepted);
            }
            Event::ExternalOwnerLost(domain) => {
                if !matches!(
                    domain_owners.get(&domain),
                    Some(DomainOwner::Accepted | DomainOwner::Fenced)
                ) {
                    return Err("external domain owner loss without accepted owner");
                }
                domain_owners.insert(domain, DomainOwner::Lost);
                unresolved.extend(
                    pending
                        .iter()
                        .filter(|(pending_domain, _)| *pending_domain == domain)
                        .copied(),
                );
            }
            Event::ExternalDomainFenced(domain) => {
                let key_is_pending = pending
                    .iter()
                    .any(|(pending_domain, _)| *pending_domain == domain);
                let key_is_unresolved = unresolved
                    .iter()
                    .any(|(pending_domain, _)| *pending_domain == domain);
                let key_has_conflict = conflicts
                    .iter()
                    .any(|(pending_domain, _)| *pending_domain == domain);
                if domain_owners.get(&domain) != Some(&DomainOwner::Accepted)
                    || key_is_pending
                    || key_is_unresolved
                    || key_has_conflict
                {
                    return Err("external domain fenced without accepted owner and resolved work");
                }
                domain_owners.insert(domain, DomainOwner::Fenced);
            }
            Event::OperationAdmitted(domain, id) => {
                if domain_owners.get(&domain) != Some(&DomainOwner::Accepted)
                    || !publication_acknowledged
                    || cancelled
                    || lifecycle_finished
                    || owner == Owner::Lost
                    || next_admission.get(&domain).copied().unwrap_or(0) != id
                {
                    return Err("external operation admitted without domain owner or sequence");
                }
                next_admission.insert(
                    domain,
                    id.checked_add(1).ok_or("admission sequence overflow")?,
                );
                pending.insert((domain, id));
                unresolved.insert((domain, id));
            }
            Event::Completion(domain, id, effect) => {
                let key = (domain, id);
                if !pending.contains(&key) {
                    conflicts.insert(key);
                    unresolved.insert(key);
                    known_effects.insert((domain, id, effect));
                    continue;
                }
                known_effects.insert((domain, id, effect));
                if owner == Owner::Lost
                    || cancelled
                    || lifecycle_finished
                    || restart_seen
                    || domain_owners[&domain] != DomainOwner::Accepted
                {
                    unresolved.insert(key);
                    continue;
                }
                if effect == Effect::Unknown {
                    unresolved.insert(key);
                    continue;
                }
                let expected = next_completion.get(&domain).copied().unwrap_or(0);
                if id != expected {
                    conflicts.insert(key);
                    unresolved.insert(key);
                    continue;
                }
                next_completion.insert(
                    domain,
                    expected
                        .checked_add(1)
                        .ok_or("completion sequence overflow")?,
                );
                pending.remove(&key);
                unresolved.remove(&key);
            }
            Event::TaskCompleted => lifecycle_finished = true,
            Event::OrdinaryCleanup => {}
            Event::ModeledRestart => {
                let visible_without_ack = publication_visible && !publication_acknowledged;
                owner = Owner::Coordinator;
                engine_lease = false;
                handoff_offered = false;
                cancelled = false;
                lifecycle_finished = true;
                restart_seen = true;
                publication_acknowledged = false;
                publication_started = false;
                snapshot = None;
                for domain_owner in domain_owners.values_mut() {
                    *domain_owner = DomainOwner::Unknown;
                }
                if visible_without_ack {
                    publication_uncertain = true;
                }
                unresolved.extend(pending.iter().copied());
            }
            Event::ReopenParticipation => {
                return Err("no modeled transition may reopen participation");
            }
            Event::ClearUnresolved(domain, id) => {
                let key = (domain, id);
                if unresolved.contains(&key) || conflicts.contains(&key) || pending.contains(&key) {
                    return Err("completion cleared unresolved or conflicting obligation");
                }
            }
        }
    }
    let _monotonic_evidence = (known_effects, unresolved, conflicts);
    Ok(())
}

fn sample_anchor() -> AnchorTuple {
    AnchorTuple {
        committed_id: [0x42; 32],
        committed_height: 17,
        current_view: 19,
        lock: Some(([0x24; 32], 18)),
    }
}

fn acknowledged_intent() -> LifecycleModel {
    let mut model = acknowledged_intent_without_external_fences();
    for domain in EXTERNAL_DOMAINS {
        model.record(Event::ExternalOwnerAccepted(domain));
        model.record(Event::ExternalDomainFenced(domain));
    }
    model
}

fn acknowledged_intent_without_external_fences() -> LifecycleModel {
    let mut model = LifecycleModel::default();
    model.record(Event::AcquireInitiatorLease);
    model.record(Event::SnapshotCaptured(sample_anchor()));
    model.record(Event::PublishStarted);
    model.record(Event::PublishVisible);
    model.record(Event::PublishAcknowledged);
    model
}

#[test]
fn owner_responsibility_survives_prelease_cancel_and_each_publication_boundary() {
    let mut before_lease = LifecycleModel::default();
    before_lease.record(Event::InitiatorCancelled);
    assert!(before_lease.validate().is_ok());
    before_lease.record(Event::AcquireInitiatorLease);
    assert!(before_lease.validate().is_err());

    let mut before_visibility = acknowledged_prefix_without_visibility();
    before_visibility.record(Event::InitiatorCancelled);
    assert!(before_visibility.validate().is_ok());

    let mut after_visibility = acknowledged_prefix_without_ack();
    after_visibility.record(Event::PublishVisible);
    after_visibility.record(Event::InitiatorCancelled);
    assert!(after_visibility.validate().is_ok());

    let mut after_ack = acknowledged_intent();
    after_ack.record(Event::InitiatorCancelled);
    after_ack.record(Event::ProtectedMutation(Owner::Initiator));
    assert!(after_ack.validate().is_err());
}

fn acknowledged_prefix_without_visibility() -> LifecycleModel {
    let mut model = LifecycleModel::default();
    model.record(Event::AcquireInitiatorLease);
    model.record(Event::SnapshotCaptured(sample_anchor()));
    model.record(Event::PublishStarted);
    model
}

fn acknowledged_prefix_without_ack() -> LifecycleModel {
    acknowledged_prefix_without_visibility()
}

#[test]
fn acknowledged_apply_handoff_cleanup_and_restart_never_clear_closed_state() {
    let mut model = acknowledged_intent();
    model.record(Event::TupleRevalidated(sample_anchor()));
    model.record(Event::ProtectedMutation(Owner::Initiator));
    model.record(Event::TaskCompleted);
    model.record(Event::OrdinaryCleanup);
    model.record(Event::LeaseDropped(Owner::Initiator));
    model.record(Event::ModeledRestart);
    assert!(model.validate().is_ok());
    model.record(Event::ReopenParticipation);
    assert!(model.validate().is_err());

    let mut restarted = acknowledged_intent();
    restarted.record(Event::TaskCompleted);
    restarted.record(Event::ModeledRestart);
    restarted.record(Event::AcquireInitiatorLease);
    assert!(restarted.validate().is_err());

    let mut after_task_completion = acknowledged_intent();
    after_task_completion.record(Event::TaskCompleted);
    after_task_completion.record(Event::ProtectedMutation(Owner::Initiator));
    assert!(after_task_completion.validate().is_err());
}

#[test]
fn publication_failures_and_unacknowledged_visibility_never_admit_mutation() {
    for visibility in [
        Visibility::NotVisible,
        Visibility::Visible,
        Visibility::Unknown,
    ] {
        let mut model = acknowledged_prefix_without_visibility();
        model.record(Event::PublishFailed(visibility));
        model.record(Event::ProtectedMutation(Owner::Initiator));
        assert!(model.validate().is_err(), "{visibility:?}");
    }

    let mut visible_unacknowledged = acknowledged_prefix_without_visibility();
    visible_unacknowledged.record(Event::PublishVisible);
    visible_unacknowledged.record(Event::ModeledRestart);
    assert!(visible_unacknowledged.validate().is_ok());

    let mut failed_republication = acknowledged_intent();
    failed_republication.record(Event::PublishFailed(Visibility::Visible));
    failed_republication.record(Event::ProtectedMutation(Owner::Initiator));
    assert!(failed_republication.validate().is_err());
}

#[test]
fn lease_drop_and_supervisor_loss_keep_refusal_owned_or_lost_not_reopened() {
    let mut dropped = LifecycleModel::default();
    dropped.record(Event::AcquireInitiatorLease);
    dropped.record(Event::LeaseDropped(Owner::Initiator));
    dropped.record(Event::ProtectedMutation(Owner::Initiator));
    assert!(dropped.validate().is_err());

    let mut transferred = acknowledged_intent();
    transferred.record(Event::SupervisorHandoffOffered);
    transferred.record(Event::SupervisorAcceptedHandoff);
    transferred.record(Event::InitiatorCancelled);
    transferred.record(Event::ProtectedMutation(Owner::Supervisor));
    transferred.record(Event::SupervisorLost);
    transferred.record(Event::ProtectedMutation(Owner::Supervisor));
    assert!(transferred.validate().is_err());

    let mut late = acknowledged_intent_without_external_fences();
    late.record(Event::ExternalOwnerAccepted(Domain::Callback));
    late.record(Event::OperationAdmitted(Domain::Callback, 0));
    late.record(Event::SupervisorHandoffOffered);
    late.record(Event::SupervisorAcceptedHandoff);
    late.record(Event::SupervisorLost);
    late.record(Event::Completion(
        Domain::Callback,
        0,
        Effect::EffectObserved,
    ));
    assert!(late.validate().is_ok());
}

#[test]
fn each_handoff_boundary_keeps_an_owner_or_refuses_mutation() {
    let mut offered_only = acknowledged_intent();
    offered_only.record(Event::SupervisorHandoffOffered);
    offered_only.record(Event::InitiatorCancelled);
    offered_only.record(Event::ProtectedMutation(Owner::Supervisor));
    assert!(offered_only.validate().is_err());

    let mut accepted = acknowledged_intent();
    accepted.record(Event::SupervisorHandoffOffered);
    accepted.record(Event::SupervisorAcceptedHandoff);
    accepted.record(Event::InitiatorCancelled);
    accepted.record(Event::ProtectedMutation(Owner::Supervisor));
    assert!(accepted.validate().is_ok());

    let mut dropped_after_ack = acknowledged_intent();
    dropped_after_ack.record(Event::LeaseDropped(Owner::Initiator));
    dropped_after_ack.record(Event::ProtectedMutation(Owner::Initiator));
    assert!(dropped_after_ack.validate().is_err());
}

#[test]
fn accepted_supervisor_can_finish_publication_after_initiator_cancellation() {
    let mut model = acknowledged_prefix_without_visibility();
    model.record(Event::SupervisorHandoffOffered);
    model.record(Event::SupervisorAcceptedHandoff);
    model.record(Event::InitiatorCancelled);
    model.record(Event::PublishVisible);
    model.record(Event::PublishAcknowledged);
    for domain in EXTERNAL_DOMAINS {
        model.record(Event::ExternalOwnerAccepted(domain));
        model.record(Event::ExternalDomainFenced(domain));
    }
    model.record(Event::ProtectedMutation(Owner::Supervisor));
    assert!(model.validate().is_ok());
}

#[test]
fn external_effect_domains_remain_unknown_without_independent_ownership() {
    let accepted = acknowledged_intent_without_external_fences();
    for domain in EXTERNAL_DOMAINS {
        let mut trace = accepted.trace.clone();
        trace.push(Event::OperationAdmitted(domain, 0));
        assert!(
            trace_is_valid(&trace).is_err(),
            "{domain:?} was implicitly fenced"
        );
        trace.pop();
        trace.push(Event::ProtectedMutation(Owner::Initiator));
        assert!(trace_is_valid(&trace).is_err(), "{domain:?} defaulted open");
    }

    let mut lost_domain = acknowledged_intent_without_external_fences();
    lost_domain.record(Event::ExternalOwnerAccepted(Domain::Snapshot));
    lost_domain.record(Event::OperationAdmitted(Domain::Snapshot, 0));
    lost_domain.record(Event::ExternalOwnerLost(Domain::Snapshot));
    lost_domain.record(Event::Completion(
        Domain::Snapshot,
        0,
        Effect::EffectObserved,
    ));
    lost_domain.record(Event::ClearUnresolved(Domain::Snapshot, 0));
    assert!(lost_domain.validate().is_err());
}

#[test]
fn independently_owned_and_completed_domain_can_be_fenced_without_erasing_effect() {
    let mut model = acknowledged_intent_without_external_fences();
    model.record(Event::ExternalOwnerAccepted(Domain::Storage));
    model.record(Event::OperationAdmitted(Domain::Storage, 0));
    model.record(Event::Completion(
        Domain::Storage,
        0,
        Effect::EffectObserved,
    ));
    model.record(Event::ExternalDomainFenced(Domain::Storage));
    for domain in [
        Domain::Signer,
        Domain::Snapshot,
        Domain::Callback,
        Domain::Outbound,
    ] {
        model.record(Event::ExternalOwnerAccepted(domain));
        model.record(Event::ExternalDomainFenced(domain));
    }
    model.record(Event::ProtectedMutation(Owner::Initiator));
    assert!(model.validate().is_ok());
}

#[test]
fn late_duplicate_and_out_of_order_completions_preserve_effects_unknown_and_conflicts() {
    let mut late = acknowledged_intent_without_external_fences();
    late.record(Event::ExternalOwnerAccepted(Domain::Signer));
    late.record(Event::OperationAdmitted(Domain::Signer, 0));
    late.record(Event::OperationAdmitted(Domain::Signer, 1));
    late.record(Event::InitiatorCancelled);
    late.record(Event::Completion(Domain::Signer, 0, Effect::EffectObserved));
    late.record(Event::Completion(Domain::Signer, 1, Effect::Unknown));
    assert!(late.validate().is_ok());
    late.record(Event::ClearUnresolved(Domain::Signer, 0));
    assert!(late.validate().is_err());

    let mut duplicate = acknowledged_intent_without_external_fences();
    duplicate.record(Event::ExternalOwnerAccepted(Domain::Storage));
    duplicate.record(Event::OperationAdmitted(Domain::Storage, 0));
    duplicate.record(Event::Completion(
        Domain::Storage,
        0,
        Effect::EffectObserved,
    ));
    duplicate.record(Event::Completion(Domain::Storage, 0, Effect::NoEffect));
    duplicate.record(Event::ClearUnresolved(Domain::Storage, 0));
    assert!(duplicate.validate().is_err());

    let mut out_of_order = acknowledged_intent_without_external_fences();
    out_of_order.record(Event::ExternalOwnerAccepted(Domain::Outbound));
    out_of_order.record(Event::OperationAdmitted(Domain::Outbound, 0));
    out_of_order.record(Event::OperationAdmitted(Domain::Outbound, 1));
    out_of_order.record(Event::Completion(Domain::Outbound, 1, Effect::NoEffect));
    out_of_order.record(Event::ClearUnresolved(Domain::Outbound, 1));
    assert!(out_of_order.validate().is_err());
}

fn defective_trace(kind: &str) -> Vec<Event> {
    match kind {
        "drop-reopens" => vec![
            Event::AcquireInitiatorLease,
            Event::LeaseDropped(Owner::Initiator),
            Event::ReopenParticipation,
        ],
        "transfer-before-acceptance" => vec![
            Event::AcquireInitiatorLease,
            Event::SupervisorAcceptedHandoff,
        ],
        "aba-tuple-equality" => vec![
            Event::AcquireInitiatorLease,
            Event::SnapshotCaptured(sample_anchor()),
            Event::PublishStarted,
            Event::PublishVisible,
            Event::PublishAcknowledged,
            Event::InterveningMutation(sample_anchor()),
            Event::TupleRevalidated(sample_anchor()),
            Event::ProtectedMutation(Owner::Initiator),
        ],
        "late-completion-clears-unknown" => vec![
            Event::AcquireInitiatorLease,
            Event::SnapshotCaptured(sample_anchor()),
            Event::PublishStarted,
            Event::PublishVisible,
            Event::PublishAcknowledged,
            Event::ExternalOwnerAccepted(Domain::Signer),
            Event::OperationAdmitted(Domain::Signer, 0),
            Event::InitiatorCancelled,
            Event::Completion(Domain::Signer, 0, Effect::EffectObserved),
            Event::ClearUnresolved(Domain::Signer, 0),
        ],
        "duplicate-completion-clears-conflict" => vec![
            Event::AcquireInitiatorLease,
            Event::SnapshotCaptured(sample_anchor()),
            Event::PublishStarted,
            Event::PublishVisible,
            Event::PublishAcknowledged,
            Event::ExternalOwnerAccepted(Domain::Storage),
            Event::OperationAdmitted(Domain::Storage, 0),
            Event::Completion(Domain::Storage, 0, Effect::EffectObserved),
            Event::Completion(Domain::Storage, 0, Effect::NoEffect),
            Event::ClearUnresolved(Domain::Storage, 0),
        ],
        _ => panic!("unknown defective lifecycle trace"),
    }
}

#[test]
fn shared_lifecycle_checker_accepts_closed_trace_and_rejects_all_defects() {
    let valid = acknowledged_intent();
    assert!(valid.validate().is_ok());
    for defect in [
        "drop-reopens",
        "transfer-before-acceptance",
        "aba-tuple-equality",
        "late-completion-clears-unknown",
        "duplicate-completion-clears-conflict",
    ] {
        assert!(
            trace_is_valid(&defective_trace(defect)).is_err(),
            "checker accepted {defect}"
        );
    }
}

#[test]
#[ignore = "parent test launches this deliberately defective lifecycle trace"]
fn negative_control_dropped_lease_reopens_participation_must_fail() {
    assert!(
        trace_is_valid(&defective_trace("drop-reopens")).is_ok(),
        "shared lifecycle checker rejected participation reopened after lease drop"
    );
}

#[test]
#[ignore = "parent test launches this deliberately defective lifecycle trace"]
fn negative_control_handoff_before_acceptance_must_fail() {
    assert!(
        trace_is_valid(&defective_trace("transfer-before-acceptance")).is_ok(),
        "shared lifecycle checker rejected transfer before supervisor acceptance"
    );
}

#[test]
#[ignore = "parent test launches this deliberately defective lifecycle trace"]
fn negative_control_aba_tuple_equality_must_fail() {
    assert!(
        trace_is_valid(&defective_trace("aba-tuple-equality")).is_ok(),
        "shared lifecycle checker rejected ABA mutation accepted by tuple equality"
    );
}

#[test]
#[ignore = "parent test launches this deliberately defective lifecycle trace"]
fn negative_control_late_completion_clears_unknown_must_fail() {
    assert!(
        trace_is_valid(&defective_trace("late-completion-clears-unknown")).is_ok(),
        "shared lifecycle checker rejected late completion clearing Unknown"
    );
}

#[test]
#[ignore = "parent test launches this deliberately defective lifecycle trace"]
fn negative_control_duplicate_completion_clears_conflict_must_fail() {
    assert!(
        trace_is_valid(&defective_trace("duplicate-completion-clears-conflict")).is_ok(),
        "shared lifecycle checker rejected duplicate completion clearing conflict"
    );
}

#[test]
fn negative_control_children_fail_and_corrected_lifecycle_checker_passes() {
    for (name, diagnostic) in [
        (
            "negative_control_dropped_lease_reopens_participation_must_fail",
            "shared lifecycle checker rejected participation reopened after lease drop",
        ),
        (
            "negative_control_handoff_before_acceptance_must_fail",
            "shared lifecycle checker rejected transfer before supervisor acceptance",
        ),
        (
            "negative_control_aba_tuple_equality_must_fail",
            "shared lifecycle checker rejected ABA mutation accepted by tuple equality",
        ),
        (
            "negative_control_late_completion_clears_unknown_must_fail",
            "shared lifecycle checker rejected late completion clearing Unknown",
        ),
        (
            "negative_control_duplicate_completion_clears_conflict_must_fail",
            "shared lifecycle checker rejected duplicate completion clearing conflict",
        ),
    ] {
        let output = Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--ignored",
                "--exact",
                name,
                "--nocapture",
                "--test-threads=1",
            ])
            .output()
            .expect("launch negative-control child");
        assert!(!output.status.success(), "{name} unexpectedly passed");
        let combined = String::from_utf8_lossy(&output.stdout).to_string()
            + &String::from_utf8_lossy(&output.stderr);
        assert!(combined.contains(diagnostic), "{name}: {combined}");
        println!(
            "EXPECTED NEGATIVE CONTROL: {name} failed with status {:?}: {diagnostic}",
            output.status.code()
        );
    }
    assert!(acknowledged_intent().validate().is_ok());
    println!("CORRECTED CONTROL: closed acknowledged intent trace accepted");
}
