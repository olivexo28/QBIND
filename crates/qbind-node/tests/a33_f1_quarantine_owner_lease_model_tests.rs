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
    LatePublicationObserved(Owner, Visibility),
    OperationCancelled,
    InitiatorTaskEnded,
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
    let mut operation_cancelled = false;
    let mut initiator_task_ended = false;
    let mut publication_started = false;
    let mut publication_visible = false;
    let mut publication_acknowledged = false;
    let mut publication_uncertain = false;
    let mut snapshot = None;
    let mut revalidated_after_ack = false;
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
        if !matches!(
            event,
            Event::TupleRevalidated(_) | Event::ProtectedMutation(_)
        ) {
            revalidated_after_ack = false;
        }
        match *event {
            Event::AcquireInitiatorLease => {
                if owner != Owner::Coordinator
                    || operation_cancelled
                    || initiator_task_ended
                    || lifecycle_finished
                    || restart_seen
                {
                    return Err("initiator acquired admission outside coordinator handoff");
                }
                owner = Owner::Initiator;
                engine_lease = true;
            }
            Event::SnapshotCaptured(tuple) => {
                if owner != Owner::Initiator
                    || !engine_lease
                    || operation_cancelled
                    || snapshot.is_some()
                    || publication_started
                {
                    return Err(
                        "starting snapshot requires a live initiator lease before publication and one capture",
                    );
                }
                snapshot = Some(tuple);
            }
            Event::PublishStarted => {
                if owner != Owner::Initiator
                    || !engine_lease
                    || snapshot.is_none()
                    || operation_cancelled
                {
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
            Event::LatePublicationObserved(observer, visibility) => {
                if !publication_started {
                    return Err("late publication observation without a started publication");
                }
                if observer == Owner::Lost || (observer == Owner::Coordinator && restart_seen) {
                    if observer != owner {
                        return Err("unowned publication observation while an owner is active");
                    }
                    publication_uncertain |= visibility != Visibility::NotVisible;
                    if visibility == Visibility::Visible {
                        publication_visible = true;
                    }
                    publication_acknowledged = false;
                } else {
                    if observer != owner
                        || !engine_lease
                        || !matches!(owner, Owner::Initiator | Owner::Supervisor)
                    {
                        return Err("late publication observation lacks responsible owner");
                    }
                    publication_uncertain |= visibility == Visibility::Unknown;
                    if visibility == Visibility::Visible {
                        publication_visible = true;
                    }
                    if visibility == Visibility::NotVisible {
                        publication_failed = true;
                    }
                    publication_acknowledged = false;
                }
            }
            Event::PublishAcknowledged => {
                if !publication_visible
                    || publication_uncertain
                    || publication_failed
                    || !engine_lease
                    || !matches!(owner, Owner::Initiator | Owner::Supervisor)
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
            Event::OperationCancelled => {
                operation_cancelled = true;
                unresolved.extend(pending.iter().copied());
            }
            Event::InitiatorTaskEnded => {
                initiator_task_ended = true;
                if owner == Owner::Initiator {
                    owner = Owner::Lost;
                    engine_lease = false;
                    lease_invalidated = true;
                    publication_uncertain |= publication_started && !publication_acknowledged;
                    unresolved.extend(pending.iter().copied());
                }
            }
            Event::SupervisorHandoffOffered => {
                if owner != Owner::Initiator || !engine_lease || operation_cancelled {
                    return Err("handoff offered without initiator ownership");
                }
                handoff_offered = true;
            }
            Event::SupervisorAcceptedHandoff => {
                if owner != Owner::Initiator
                    || !engine_lease
                    || !handoff_offered
                    || operation_cancelled
                {
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
                lease_invalidated = true;
                publication_uncertain |= publication_started && !publication_acknowledged;
                unresolved.extend(pending.iter().copied());
            }
            Event::SupervisorLost => {
                if owner != Owner::Supervisor {
                    return Err("supervisor loss reported without supervisor ownership");
                }
                owner = Owner::Lost;
                engine_lease = false;
                lease_invalidated = true;
                publication_uncertain |= publication_started && !publication_acknowledged;
                unresolved.extend(pending.iter().copied());
            }
            Event::InterveningMutation(_) => {
                if engine_lease {
                    lease_invalidated = true;
                    owner = Owner::Lost;
                    engine_lease = false;
                    publication_uncertain |= publication_started && !publication_acknowledged;
                    unresolved.extend(pending.iter().copied());
                }
            }
            Event::TupleRevalidated(tuple) => {
                if lease_invalidated {
                    return Err("tuple equality cannot restore a lost or invalidated lease");
                }
                if !publication_acknowledged {
                    return Err("tuple revalidation must follow acknowledged publication");
                }
                if operation_cancelled {
                    return Err("operation cancellation forbids revalidation for mutation");
                }
                if snapshot != Some(tuple) {
                    return Err("tuple revalidation detected changed state");
                }
                if !engine_lease || !matches!(owner, Owner::Initiator | Owner::Supervisor) {
                    return Err("tuple revalidated without continuous exclusive ownership");
                }
                revalidated_after_ack = true;
            }
            Event::ProtectedMutation(mutation_owner) => {
                if operation_cancelled {
                    return Err("operation cancellation forbids protected mutation");
                }
                if !revalidated_after_ack {
                    return Err("protected mutation requires post-ack tuple revalidation");
                }
                if mutation_owner != owner
                    || !engine_lease
                    || !matches!(owner, Owner::Initiator | Owner::Supervisor)
                    || !publication_acknowledged
                    || publication_uncertain
                    || lease_invalidated
                    || lifecycle_finished
                    || domain_owners
                        .values()
                        .any(|domain_owner| *domain_owner != DomainOwner::Fenced)
                    || !unresolved.is_empty()
                {
                    return Err(
                        "protected mutation lacks live owner lease or resolved obligations",
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
                    || publication_acknowledged
                    || publication_failed
                    || operation_cancelled
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
                    || operation_cancelled
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
                let unacknowledged_publication = publication_started && !publication_acknowledged;
                owner = Owner::Coordinator;
                engine_lease = false;
                handoff_offered = false;
                lifecycle_finished = true;
                restart_seen = true;
                publication_acknowledged = false;
                revalidated_after_ack = false;
                snapshot = None;
                for domain_owner in domain_owners.values_mut() {
                    *domain_owner = DomainOwner::Unknown;
                }
                if unacknowledged_publication {
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
        if matches!(event, Event::ProtectedMutation(_)) {
            revalidated_after_ack = false;
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

fn intent_with_preexisting_work(domain: Domain, ids: &[u64]) -> LifecycleModel {
    let mut model = LifecycleModel::default();
    model.record(Event::ExternalOwnerAccepted(domain));
    for id in ids {
        model.record(Event::OperationAdmitted(domain, *id));
    }
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
    before_lease.record(Event::OperationCancelled);
    assert!(before_lease.validate().is_ok());
    before_lease.record(Event::AcquireInitiatorLease);
    assert!(before_lease.validate().is_err());

    let mut before_visibility = acknowledged_prefix_without_visibility();
    before_visibility.record(Event::OperationCancelled);
    assert!(before_visibility.validate().is_ok());

    let mut after_visibility = acknowledged_prefix_without_ack();
    after_visibility.record(Event::PublishVisible);
    after_visibility.record(Event::OperationCancelled);
    assert!(after_visibility.validate().is_ok());

    let mut after_ack = acknowledged_intent();
    after_ack.record(Event::OperationCancelled);
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
    transferred.record(Event::OperationCancelled);
    transferred.record(Event::ProtectedMutation(Owner::Supervisor));
    transferred.record(Event::SupervisorLost);
    transferred.record(Event::ProtectedMutation(Owner::Supervisor));
    assert!(transferred.validate().is_err());

    let mut late = intent_with_preexisting_work(Domain::Callback, &[0]);
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
    offered_only.record(Event::OperationCancelled);
    offered_only.record(Event::ProtectedMutation(Owner::Supervisor));
    assert!(offered_only.validate().is_err());

    let mut accepted = acknowledged_intent();
    accepted.record(Event::SupervisorHandoffOffered);
    accepted.record(Event::SupervisorAcceptedHandoff);
    accepted.record(Event::InitiatorTaskEnded);
    accepted.record(Event::TupleRevalidated(sample_anchor()));
    accepted.record(Event::ProtectedMutation(Owner::Supervisor));
    assert!(accepted.validate().is_ok());

    let mut dropped_after_ack = acknowledged_intent();
    dropped_after_ack.record(Event::LeaseDropped(Owner::Initiator));
    dropped_after_ack.record(Event::ProtectedMutation(Owner::Initiator));
    assert!(dropped_after_ack.validate().is_err());
}

#[test]
fn accepted_supervisor_can_finish_publication_after_initiator_task_end() {
    let mut model = acknowledged_prefix_without_visibility();
    model.record(Event::SupervisorHandoffOffered);
    model.record(Event::SupervisorAcceptedHandoff);
    model.record(Event::InitiatorTaskEnded);
    model.record(Event::LatePublicationObserved(
        Owner::Supervisor,
        Visibility::Visible,
    ));
    model.record(Event::PublishAcknowledged);
    for domain in EXTERNAL_DOMAINS {
        model.record(Event::ExternalOwnerAccepted(domain));
        model.record(Event::ExternalDomainFenced(domain));
    }
    model.record(Event::TupleRevalidated(sample_anchor()));
    model.record(Event::ProtectedMutation(Owner::Supervisor));
    assert!(model.validate().is_ok());
}

#[test]
fn task_end_after_handoff_preserves_owner_but_operation_cancel_refuses() {
    let mut model = acknowledged_intent();
    model.record(Event::SupervisorHandoffOffered);
    model.record(Event::SupervisorAcceptedHandoff);
    model.record(Event::InitiatorTaskEnded);
    model.record(Event::TupleRevalidated(sample_anchor()));
    assert!(model.validate().is_ok());
    model.record(Event::ProtectedMutation(Owner::Supervisor));
    assert!(model.validate().is_ok());

    let mut cancelled_after_handoff = acknowledged_intent();
    cancelled_after_handoff.record(Event::SupervisorHandoffOffered);
    cancelled_after_handoff.record(Event::SupervisorAcceptedHandoff);
    cancelled_after_handoff.record(Event::InitiatorTaskEnded);
    cancelled_after_handoff.record(Event::OperationCancelled);
    assert!(cancelled_after_handoff.validate().is_ok());
    cancelled_after_handoff.record(Event::ProtectedMutation(Owner::Supervisor));
    assert_eq!(
        cancelled_after_handoff.validate(),
        Err("operation cancellation forbids protected mutation")
    );
}

#[test]
fn preexisting_work_blocks_mutation_until_observed_and_unknown_stays_blocked() {
    let mut pending = intent_with_preexisting_work(Domain::Storage, &[0]);
    pending.record(Event::ExternalOwnerAccepted(Domain::Signer));
    pending.record(Event::ExternalDomainFenced(Domain::Signer));
    for domain in [Domain::Snapshot, Domain::Callback, Domain::Outbound] {
        pending.record(Event::ExternalOwnerAccepted(domain));
        pending.record(Event::ExternalDomainFenced(domain));
    }
    pending.record(Event::TupleRevalidated(sample_anchor()));
    assert!(pending.validate().is_ok());
    pending.record(Event::ProtectedMutation(Owner::Initiator));
    assert_eq!(
        pending.validate(),
        Err("protected mutation lacks live owner lease or resolved obligations")
    );

    let mut observed = intent_with_preexisting_work(Domain::Storage, &[0]);
    observed.record(Event::Completion(
        Domain::Storage,
        0,
        Effect::EffectObserved,
    ));
    observed.record(Event::ExternalDomainFenced(Domain::Storage));
    for domain in [
        Domain::Signer,
        Domain::Snapshot,
        Domain::Callback,
        Domain::Outbound,
    ] {
        observed.record(Event::ExternalOwnerAccepted(domain));
        observed.record(Event::ExternalDomainFenced(domain));
    }
    observed.record(Event::TupleRevalidated(sample_anchor()));
    observed.record(Event::ProtectedMutation(Owner::Initiator));
    assert!(observed.validate().is_ok());

    let mut unknown = intent_with_preexisting_work(Domain::Storage, &[0]);
    unknown.record(Event::Completion(Domain::Storage, 0, Effect::Unknown));
    for domain in [
        Domain::Signer,
        Domain::Snapshot,
        Domain::Callback,
        Domain::Outbound,
    ] {
        unknown.record(Event::ExternalOwnerAccepted(domain));
        unknown.record(Event::ExternalDomainFenced(domain));
    }
    unknown.record(Event::TupleRevalidated(sample_anchor()));
    unknown.record(Event::ProtectedMutation(Owner::Initiator));
    assert_eq!(
        unknown.validate(),
        Err("protected mutation lacks live owner lease or resolved obligations")
    );
}

#[test]
fn substituted_starting_snapshot_after_ack_is_rejected_and_original_remains_usable() {
    let starting_snapshot = sample_anchor();
    let mut substituted_snapshot = starting_snapshot;
    substituted_snapshot.committed_id = [0x99; 32];
    assert_ne!(starting_snapshot, substituted_snapshot);

    let acknowledged = acknowledged_intent_without_external_fences();
    assert_eq!(acknowledged.validate(), Ok(()));

    let mut substituted_trace = acknowledged.trace.clone();
    substituted_trace.push(Event::SnapshotCaptured(substituted_snapshot));
    assert_eq!(
        trace_is_valid(&substituted_trace),
        Err("starting snapshot requires a live initiator lease before publication and one capture")
    );

    let mut original_trace = acknowledged.trace;
    for domain in EXTERNAL_DOMAINS {
        original_trace.push(Event::ExternalOwnerAccepted(domain));
        original_trace.push(Event::ExternalDomainFenced(domain));
    }
    original_trace.push(Event::TupleRevalidated(starting_snapshot));
    original_trace.push(Event::ProtectedMutation(Owner::Initiator));
    assert_eq!(trace_is_valid(&original_trace), Ok(()));
}

#[test]
fn tuple_revalidation_is_post_ack_and_stales_before_a_later_mutation() {
    let mut before_ack = acknowledged_prefix_without_visibility();
    before_ack.record(Event::TupleRevalidated(sample_anchor()));
    assert_eq!(
        before_ack.validate(),
        Err("tuple revalidation must follow acknowledged publication")
    );

    let mut stale = acknowledged_intent();
    stale.record(Event::TupleRevalidated(sample_anchor()));
    stale.record(Event::OrdinaryCleanup);
    stale.record(Event::ProtectedMutation(Owner::Initiator));
    assert_eq!(
        stale.validate(),
        Err("protected mutation requires post-ack tuple revalidation")
    );

    let mut changed = acknowledged_intent();
    let mut changed_anchor = sample_anchor();
    changed_anchor.current_view += 1;
    changed.record(Event::TupleRevalidated(changed_anchor));
    assert_eq!(
        changed.validate(),
        Err("tuple revalidation detected changed state")
    );
}

#[test]
fn restart_preserves_pending_outcomes_and_late_publication_uncertainty() {
    let mut restarted = intent_with_preexisting_work(Domain::Outbound, &[0]);
    restarted.record(Event::ModeledRestart);
    restarted.record(Event::Completion(
        Domain::Outbound,
        0,
        Effect::EffectObserved,
    ));
    assert!(restarted.validate().is_ok());
    restarted.record(Event::ClearUnresolved(Domain::Outbound, 0));
    assert!(restarted.validate().is_err());

    let mut retained_evidence = intent_with_preexisting_work(Domain::Storage, &[0, 1]);
    retained_evidence.record(Event::Completion(
        Domain::Storage,
        0,
        Effect::EffectObserved,
    ));
    retained_evidence.record(Event::Completion(Domain::Storage, 1, Effect::Unknown));
    retained_evidence.record(Event::ModeledRestart);
    retained_evidence.record(Event::Completion(Domain::Storage, 0, Effect::NoEffect));
    assert!(retained_evidence.validate().is_ok());
    retained_evidence.record(Event::ClearUnresolved(Domain::Storage, 0));
    assert!(retained_evidence.validate().is_err());
    retained_evidence.trace.pop();
    retained_evidence.record(Event::ClearUnresolved(Domain::Storage, 1));
    assert!(retained_evidence.validate().is_err());

    let mut late_visibility = acknowledged_prefix_without_visibility();
    late_visibility.record(Event::ModeledRestart);
    late_visibility.record(Event::LatePublicationObserved(
        Owner::Coordinator,
        Visibility::Visible,
    ));
    assert!(late_visibility.validate().is_ok());
    late_visibility.record(Event::PublishAcknowledged);
    assert_eq!(
        late_visibility.validate(),
        Err("publication acknowledged without certain visible intent")
    );
}

#[test]
fn late_publication_after_cancel_is_observed_but_never_authorizes_mutation() {
    let mut supervisor = acknowledged_prefix_without_visibility();
    supervisor.record(Event::SupervisorHandoffOffered);
    supervisor.record(Event::SupervisorAcceptedHandoff);
    supervisor.record(Event::OperationCancelled);
    supervisor.record(Event::InitiatorTaskEnded);
    supervisor.record(Event::LatePublicationObserved(
        Owner::Supervisor,
        Visibility::Visible,
    ));
    supervisor.record(Event::PublishAcknowledged);
    assert!(supervisor.validate().is_ok());
    supervisor.record(Event::ProtectedMutation(Owner::Supervisor));
    assert_eq!(
        supervisor.validate(),
        Err("operation cancellation forbids protected mutation")
    );

    let mut lost = acknowledged_prefix_without_visibility();
    lost.record(Event::InitiatorTaskEnded);
    lost.record(Event::LatePublicationObserved(
        Owner::Lost,
        Visibility::Visible,
    ));
    assert!(lost.validate().is_ok());
    lost.record(Event::PublishAcknowledged);
    assert_eq!(
        lost.validate(),
        Err("publication acknowledged without certain visible intent")
    );
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

    let mut lost_domain = intent_with_preexisting_work(Domain::Snapshot, &[0]);
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
    let mut model = intent_with_preexisting_work(Domain::Storage, &[0]);
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
    model.record(Event::TupleRevalidated(sample_anchor()));
    model.record(Event::ProtectedMutation(Owner::Initiator));
    assert!(model.validate().is_ok());
}

#[test]
fn late_duplicate_and_out_of_order_completions_preserve_effects_unknown_and_conflicts() {
    let mut late = intent_with_preexisting_work(Domain::Signer, &[0, 1]);
    late.record(Event::OperationCancelled);
    late.record(Event::Completion(Domain::Signer, 0, Effect::EffectObserved));
    late.record(Event::Completion(Domain::Signer, 1, Effect::Unknown));
    assert!(late.validate().is_ok());
    late.record(Event::ClearUnresolved(Domain::Signer, 0));
    assert!(late.validate().is_err());
    late.trace.pop();
    late.record(Event::ClearUnresolved(Domain::Signer, 1));
    assert!(late.validate().is_err());

    let mut duplicate = intent_with_preexisting_work(Domain::Storage, &[0]);
    duplicate.record(Event::Completion(
        Domain::Storage,
        0,
        Effect::EffectObserved,
    ));
    duplicate.record(Event::Completion(Domain::Storage, 0, Effect::NoEffect));
    duplicate.record(Event::ClearUnresolved(Domain::Storage, 0));
    assert!(duplicate.validate().is_err());

    let mut out_of_order = intent_with_preexisting_work(Domain::Outbound, &[0, 1]);
    out_of_order.record(Event::Completion(Domain::Outbound, 1, Effect::NoEffect));
    out_of_order.record(Event::ClearUnresolved(Domain::Outbound, 1));
    assert!(out_of_order.validate().is_err());
}

fn negative_control_case(kind: &str) -> (Vec<Event>, Event, &'static str) {
    match kind {
        "drop-reopens" => (
            vec![
                Event::AcquireInitiatorLease,
                Event::LeaseDropped(Owner::Initiator),
            ],
            Event::ReopenParticipation,
            "no modeled transition may reopen participation",
        ),
        "transfer-before-acceptance" => (
            vec![Event::AcquireInitiatorLease],
            Event::SupervisorAcceptedHandoff,
            "supervisor ownership transferred before acceptance",
        ),
        "aba-tuple-equality" => (
            vec![
                Event::AcquireInitiatorLease,
                Event::SnapshotCaptured(sample_anchor()),
                Event::PublishStarted,
                Event::PublishVisible,
                Event::PublishAcknowledged,
                Event::InterveningMutation(sample_anchor()),
            ],
            Event::TupleRevalidated(sample_anchor()),
            "tuple equality cannot restore a lost or invalidated lease",
        ),
        "late-completion-clears-unknown" => {
            let mut prefix = intent_with_preexisting_work(Domain::Signer, &[0]).trace;
            prefix.extend([
                Event::OperationCancelled,
                Event::Completion(Domain::Signer, 0, Effect::EffectObserved),
            ]);
            (
                prefix,
                Event::ClearUnresolved(Domain::Signer, 0),
                "completion cleared unresolved or conflicting obligation",
            )
        }
        "duplicate-completion-clears-conflict" => {
            let mut prefix = intent_with_preexisting_work(Domain::Storage, &[0]).trace;
            prefix.extend([
                Event::Completion(Domain::Storage, 0, Effect::EffectObserved),
                Event::Completion(Domain::Storage, 0, Effect::NoEffect),
            ]);
            (
                prefix,
                Event::ClearUnresolved(Domain::Storage, 0),
                "completion cleared unresolved or conflicting obligation",
            )
        }
        "mutation-without-revalidation" => (
            acknowledged_intent().trace,
            Event::ProtectedMutation(Owner::Initiator),
            "protected mutation requires post-ack tuple revalidation",
        ),
        "operation-cancel-after-handoff" => {
            let mut prefix = acknowledged_intent().trace;
            prefix.extend([
                Event::SupervisorHandoffOffered,
                Event::SupervisorAcceptedHandoff,
                Event::InitiatorTaskEnded,
                Event::OperationCancelled,
            ]);
            (
                prefix,
                Event::ProtectedMutation(Owner::Supervisor),
                "operation cancellation forbids protected mutation",
            )
        }
        "pending-preexisting-work" => {
            let mut prefix = intent_with_preexisting_work(Domain::Storage, &[0]).trace;
            for domain in [
                Domain::Signer,
                Domain::Snapshot,
                Domain::Callback,
                Domain::Outbound,
            ] {
                prefix.extend([
                    Event::ExternalOwnerAccepted(domain),
                    Event::ExternalDomainFenced(domain),
                ]);
            }
            prefix.push(Event::TupleRevalidated(sample_anchor()));
            (
                prefix,
                Event::ProtectedMutation(Owner::Initiator),
                "protected mutation lacks live owner lease or resolved obligations",
            )
        }
        "late-visible-after-cancel" => {
            let mut prefix = acknowledged_prefix_without_visibility().trace;
            prefix.extend([
                Event::SupervisorHandoffOffered,
                Event::SupervisorAcceptedHandoff,
                Event::OperationCancelled,
                Event::InitiatorTaskEnded,
                Event::LatePublicationObserved(Owner::Supervisor, Visibility::Visible),
                Event::PublishAcknowledged,
            ]);
            (
                prefix,
                Event::ProtectedMutation(Owner::Supervisor),
                "operation cancellation forbids protected mutation",
            )
        }
        _ => panic!("unknown defective lifecycle trace"),
    }
}

fn defective_trace(kind: &str) -> (Vec<Event>, &'static str) {
    let (mut prefix, transition, reason) = negative_control_case(kind);
    prefix.push(transition);
    (prefix, reason)
}

#[test]
fn shared_lifecycle_checker_accepts_prefixes_and_rejects_defective_transitions() {
    assert!(acknowledged_intent().validate().is_ok());
    for kind in [
        "drop-reopens",
        "transfer-before-acceptance",
        "aba-tuple-equality",
        "late-completion-clears-unknown",
        "duplicate-completion-clears-conflict",
        "mutation-without-revalidation",
        "operation-cancel-after-handoff",
        "pending-preexisting-work",
        "late-visible-after-cancel",
    ] {
        let (prefix, transition, expected_reason) = negative_control_case(kind);
        assert!(trace_is_valid(&prefix).is_ok(), "invalid prefix for {kind}");
        let mut full = prefix;
        full.push(transition);
        assert_eq!(
            trace_is_valid(&full),
            Err(expected_reason),
            "wrong rejection for {kind}"
        );
    }
}

#[test]
#[ignore = "parent test launches this deliberately defective lifecycle trace"]
fn negative_control_dropped_lease_reopens_participation_must_fail() {
    assert!(
        trace_is_valid(&defective_trace("drop-reopens").0).is_ok(),
        "negative control unexpectedly passed: no modeled transition may reopen participation"
    );
}

#[test]
#[ignore = "parent test launches this deliberately defective lifecycle trace"]
fn negative_control_handoff_before_acceptance_must_fail() {
    assert!(
        trace_is_valid(&defective_trace("transfer-before-acceptance").0).is_ok(),
        "negative control unexpectedly passed: supervisor ownership transferred before acceptance"
    );
}

#[test]
#[ignore = "parent test launches this deliberately defective lifecycle trace"]
fn negative_control_aba_tuple_equality_must_fail() {
    assert!(
        trace_is_valid(&defective_trace("aba-tuple-equality").0).is_ok(),
        "negative control unexpectedly passed: tuple equality cannot restore a lost or invalidated lease"
    );
}

#[test]
#[ignore = "parent test launches this deliberately defective lifecycle trace"]
fn negative_control_late_completion_clears_unknown_must_fail() {
    assert!(
        trace_is_valid(&defective_trace("late-completion-clears-unknown").0).is_ok(),
        "negative control unexpectedly passed: completion cleared unresolved or conflicting obligation"
    );
}

#[test]
#[ignore = "parent test launches this deliberately defective lifecycle trace"]
fn negative_control_duplicate_completion_clears_conflict_must_fail() {
    assert!(
        trace_is_valid(&defective_trace("duplicate-completion-clears-conflict").0).is_ok(),
        "negative control unexpectedly passed: completion cleared unresolved or conflicting obligation"
    );
}

#[test]
#[ignore = "parent test launches this deliberately defective lifecycle trace"]
fn negative_control_mutation_without_post_ack_revalidation_must_fail() {
    assert!(
        trace_is_valid(&defective_trace("mutation-without-revalidation").0).is_ok(),
        "negative control unexpectedly passed: protected mutation requires post-ack tuple revalidation"
    );
}

#[test]
#[ignore = "parent test launches this deliberately defective lifecycle trace"]
fn negative_control_operation_cancellation_after_handoff_must_fail() {
    assert!(
        trace_is_valid(&defective_trace("operation-cancel-after-handoff").0).is_ok(),
        "negative control unexpectedly passed: operation cancellation forbids protected mutation"
    );
}

#[test]
#[ignore = "parent test launches this deliberately defective lifecycle trace"]
fn negative_control_pending_preexisting_work_must_fail() {
    assert!(
        trace_is_valid(&defective_trace("pending-preexisting-work").0).is_ok(),
        "negative control unexpectedly passed: protected mutation lacks live owner lease or resolved obligations"
    );
}

#[test]
#[ignore = "parent test launches this deliberately defective lifecycle trace"]
fn negative_control_late_visible_after_cancel_must_fail() {
    assert!(
        trace_is_valid(&defective_trace("late-visible-after-cancel").0).is_ok(),
        "negative control unexpectedly passed: operation cancellation forbids protected mutation"
    );
}

#[test]
fn negative_control_children_fail_and_corrected_lifecycle_checker_passes() {
    for (name, kind) in [
        (
            "negative_control_dropped_lease_reopens_participation_must_fail",
            "drop-reopens",
        ),
        (
            "negative_control_handoff_before_acceptance_must_fail",
            "transfer-before-acceptance",
        ),
        (
            "negative_control_aba_tuple_equality_must_fail",
            "aba-tuple-equality",
        ),
        (
            "negative_control_late_completion_clears_unknown_must_fail",
            "late-completion-clears-unknown",
        ),
        (
            "negative_control_duplicate_completion_clears_conflict_must_fail",
            "duplicate-completion-clears-conflict",
        ),
        (
            "negative_control_mutation_without_post_ack_revalidation_must_fail",
            "mutation-without-revalidation",
        ),
        (
            "negative_control_operation_cancellation_after_handoff_must_fail",
            "operation-cancel-after-handoff",
        ),
        (
            "negative_control_pending_preexisting_work_must_fail",
            "pending-preexisting-work",
        ),
        (
            "negative_control_late_visible_after_cancel_must_fail",
            "late-visible-after-cancel",
        ),
    ] {
        let (prefix, transition, expected_reason) = negative_control_case(kind);
        assert!(
            trace_is_valid(&prefix).is_ok(),
            "{kind} prefix was rejected"
        );
        let mut defective = prefix;
        defective.push(transition);
        assert_eq!(
            trace_is_valid(&defective),
            Err(expected_reason),
            "{kind} was rejected for the wrong reason"
        );
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
        assert!(combined.contains(expected_reason), "{name}: {combined}");
        println!(
            "EXPECTED NEGATIVE CONTROL: {name} failed with status {:?}: {expected_reason}",
            output.status.code()
        );
    }
    assert!(acknowledged_intent().validate().is_ok());
    println!("CORRECTED CONTROL: closed acknowledged intent trace accepted");
}
