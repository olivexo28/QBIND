#[path = "support/a33_f1_ordered_planner.rs"]
mod model;

use model::{
    Accounting, BlockId, Candidate, EffectObservation as E, EvidenceKind, FixtureLimits, ItemPhase,
    LateEvidence, Model, PublicationPhase, PublishFault, PublishOutcome, Refusal, Terminal,
    VoteDisposition,
};

fn candidate(id: BlockId, parent: Option<BlockId>) -> Candidate {
    Candidate {
        id,
        parent,
        local_charge: 3,
        shared_evidence: None,
    }
}

fn full_lineage_model() -> (Model, Candidate) {
    let mut model = Model::new(4);
    model.add_fixture_block(1, None, false, 1, None).unwrap(); // R
    model.add_fixture_block(2, Some(1), false, 2, None).unwrap(); // A
    model.add_fixture_block(3, Some(2), false, 3, None).unwrap(); // P
    model.add_fixture_block(4, None, false, 4, None).unwrap();
    model.add_fixture_block(5, None, false, 5, None).unwrap();
    model.set_queue_for_test(vec![99, 4, 4, 5, 77, 77]).unwrap();
    (model, candidate(6, Some(3))) // C
}

#[test]
fn lineage_invariant_rejects_direct_parent_only_protection() {
    let (model, candidate) = full_lineage_model();
    assert!(
        !model
            .plan_preserves_candidate_lineage(&candidate, &[2], FixtureLimits::TEST)
            .unwrap(),
        "R -> A -> P -> C: protecting only direct parent P still permits deleting A"
    );
    assert!(model
        .plan_preserves_candidate_lineage(&candidate, &[4, 5], FixtureLimits::TEST)
        .unwrap());

    let plan = model.plan(candidate, FixtureLimits::TEST).unwrap();
    assert_eq!(plan.deficit(), 2);
    assert_eq!(plan.victims(), &[4, 5]);
    assert!(plan.protected().contains(&1));
    assert!(plan.protected().contains(&2));
    assert!(plan.protected().contains(&3));
    let mut published = model;
    assert_eq!(
        published.publish(plan, None),
        PublishOutcome::Published {
            victims: vec![4, 5],
            accounting: Accounting {
                local_bytes: 9,
                shared_bytes: 0,
            },
        }
    );
    assert!(published.blocks.contains_key(&1));
    assert!(published.blocks.contains_key(&2));
    assert!(published.blocks.contains_key(&3));
    assert!(published.blocks.contains_key(&6));
    assert!(!published.blocks.contains_key(&4));
    assert!(!published.blocks.contains_key(&5));
    // Queue traversal skips stale 99, deduplicates selected 4, and on success
    // removes every selected occurrence; unrelated stale/duplicate 77 remains.
    assert_eq!(published.queue, vec![99, 77, 77, 6]);
}

#[test]
fn capacity_zero_free_exact_and_already_over_limit_are_checked() {
    let empty_zero = Model::new(0);
    assert_eq!(
        empty_zero.plan(candidate(1, None), FixtureLimits::TEST),
        Err(Refusal::InsufficientSafeVictims {
            needed: 1,
            found: 0,
        })
    );

    let free = Model::new(1);
    let free_plan = free.plan(candidate(1, None), FixtureLimits::TEST).unwrap();
    assert_eq!(free_plan.deficit(), 0);
    assert!(free_plan.victims().is_empty());

    let mut exact = Model::new(2);
    exact.add_fixture_block(1, None, false, 1, None).unwrap();
    exact.add_fixture_block(2, None, false, 2, None).unwrap();
    let exact_plan = exact.plan(candidate(3, None), FixtureLimits::TEST).unwrap();
    assert_eq!(exact_plan.deficit(), 1);
    assert_eq!(exact_plan.victims(), &[1]);

    let mut over = Model::new(1);
    for id in 1..=3 {
        over.add_fixture_block(id, None, false, id as u64, None)
            .unwrap();
    }
    let over_plan = over.plan(candidate(4, None), FixtureLimits::TEST).unwrap();
    assert_eq!(over_plan.deficit(), 3);
    assert_eq!(over_plan.victims(), &[1, 2, 3]);
}

#[test]
fn existing_id_and_all_protected_root_ancestors_refuse_or_survive() {
    let mut existing = Model::new(2);
    existing.add_fixture_block(1, None, false, 1, None).unwrap();
    let before = existing.clone();
    assert_eq!(
        existing.plan(candidate(1, None), FixtureLimits::TEST),
        Err(Refusal::ExistingId(1))
    );
    assert_eq!(existing, before);

    let mut roots = Model::new(5);
    roots.add_fixture_block(1, None, false, 1, None).unwrap();
    roots.add_fixture_block(2, Some(1), false, 1, None).unwrap();
    roots.add_fixture_block(3, None, false, 1, None).unwrap();
    roots.add_fixture_block(4, Some(3), true, 1, None).unwrap();
    roots.add_fixture_block(5, None, false, 1, None).unwrap();
    roots.add_fixture_block(6, None, false, 1, None).unwrap();
    roots.set_protected_roots(Some(1), Some(2)).unwrap();
    let plan = roots.plan(candidate(7, None), FixtureLimits::TEST).unwrap();
    assert_eq!(plan.deficit(), 2);
    assert_eq!(plan.victims(), &[5, 6]);
    assert!(plan.protected().contains(&1), "committed path");
    assert!(plan.protected().contains(&2), "lock path");
    assert!(plan.protected().contains(&4), "own-QC block");
    assert!(
        plan.protected().contains(&3),
        "own-QC ancestor remains protected"
    );
}

#[test]
fn deterministic_fallback_and_checked_accounting_refusals_are_pure() {
    let mut fallback = Model::new(1);
    fallback.add_fixture_block(9, None, false, 1, None).unwrap();
    fallback.add_fixture_block(3, None, false, 1, None).unwrap();
    fallback.set_queue_for_test(vec![800]).unwrap();
    let fallback_plan = fallback
        .plan(candidate(10, None), FixtureLimits::TEST)
        .unwrap();
    assert_eq!(
        fallback_plan.victims(),
        &[3, 9],
        "synthetic BTreeMap fallback selects the full deficit deterministically"
    );

    let mut overflow = Model::new(2);
    overflow.add_fixture_block(1, None, false, 1, None).unwrap();
    overflow.add_fixture_block(2, None, false, 1, None).unwrap();
    let before = overflow.clone();
    let mut too_large = candidate(3, None);
    too_large.local_charge = u64::MAX;
    assert_eq!(
        overflow.plan(too_large, FixtureLimits::TEST),
        Err(Refusal::ArithmeticOverflow)
    );
    assert_eq!(
        overflow, before,
        "checked projection refuses before mutation"
    );

    let mut too_many = Model::new(0);
    for id in 1..=5 {
        too_many
            .add_fixture_block(id, None, false, 0, None)
            .unwrap();
    }
    let mut limits = FixtureLimits::TEST;
    limits.max_victims = 2;
    assert_eq!(
        too_many.plan(candidate(6, None), limits),
        Err(Refusal::VictimPlanLimit {
            needed: 6,
            limit: 2
        })
    );
}

#[test]
fn d_zero_checks_candidate_lineage_but_not_unrelated_cycles() {
    let mut model = Model::new(3);
    model.add_fixture_block(1, Some(2), false, 0, None).unwrap();
    model.add_fixture_block(2, Some(1), false, 0, None).unwrap();
    assert!(
        model.plan(candidate(3, None), FixtureLimits::TEST).is_ok(),
        "D=0 does not scan unrelated graph components"
    );
    assert_eq!(
        model.plan(candidate(4, Some(91)), FixtureLimits::TEST),
        Err(Refusal::MissingRequiredLineage(91))
    );
    assert_eq!(
        model.plan(candidate(4, Some(1)), FixtureLimits::TEST),
        Err(Refusal::CyclicRequiredLineage(1))
    );
}

#[test]
fn insufficient_complete_plan_refuses_without_changing_model() {
    let mut model = Model::new(3);
    model.add_fixture_block(1, None, false, 1, None).unwrap();
    for id in 2..=5 {
        model
            .add_fixture_block(id, None, id != 5, id as u64, None)
            .unwrap();
    }
    model.set_protected_roots(Some(2), None).unwrap();
    model.set_queue_for_test(vec![5, 5, 900, 2, 3, 4]).unwrap();
    let before = model.clone();
    assert_eq!(
        model.plan(candidate(6, Some(1)), FixtureLimits::TEST),
        Err(Refusal::InsufficientSafeVictims {
            needed: 3,
            found: 1,
        })
    );
    assert_eq!(model, before, "failed planning must be pure");
}

#[test]
fn cycles_missing_protected_paths_and_work_exhaustion_refuse() {
    let mut cyclic = Model::new(1);
    cyclic
        .add_fixture_block(1, Some(2), false, 0, None)
        .unwrap();
    cyclic
        .add_fixture_block(2, Some(1), false, 0, None)
        .unwrap();
    cyclic.set_protected_roots(None, Some(1)).unwrap();
    assert_eq!(
        cyclic.plan(candidate(3, None), FixtureLimits::TEST),
        Err(Refusal::CyclicRequiredLineage(1))
    );

    let mut missing = Model::new(1);
    missing
        .add_fixture_block(1, Some(8), false, 0, None)
        .unwrap();
    missing.set_protected_roots(Some(1), None).unwrap();
    assert_eq!(
        missing.plan(candidate(2, None), FixtureLimits::TEST),
        Err(Refusal::MissingRequiredLineage(8))
    );

    let limits = FixtureLimits {
        max_lineage_visits: 1,
        ..FixtureLimits::TEST
    };
    let mut deep = Model::new(1);
    deep.add_fixture_block(1, None, false, 0, None).unwrap();
    deep.add_fixture_block(2, Some(1), false, 0, None).unwrap();
    deep.add_fixture_block(3, Some(2), false, 0, None).unwrap();
    assert_eq!(
        deep.plan(candidate(4, Some(3)), limits),
        Err(Refusal::LineageWorkBudgetExhausted)
    );
}

#[test]
fn shared_accounting_is_released_only_after_last_owner_and_stale_plan_refuses() {
    let mut model = Model::new(2);
    model
        .add_fixture_block(1, None, false, 2, Some((7, 11)))
        .unwrap();
    model
        .add_fixture_block(2, None, false, 3, Some((7, 11)))
        .unwrap();
    let mut shared_candidate = candidate(3, None);
    shared_candidate.shared_evidence = Some((7, 11));
    let plan = model
        .plan(shared_candidate.clone(), FixtureLimits::TEST)
        .unwrap();
    assert_eq!(plan.victims(), &[1]);
    let mut published = model.clone();
    assert_eq!(
        published.publish(plan.clone(), None),
        PublishOutcome::Published {
            victims: vec![1],
            accounting: Accounting {
                local_bytes: 6,
                shared_bytes: 11,
            },
        }
    );
    assert_eq!(published.shared_charges.get(&7), Some(&11));

    model.set_queue_for_test(vec![1, 2]).unwrap();
    let before_publish = model.clone();
    assert_eq!(
        model.publish(plan, None),
        PublishOutcome::Refused(Refusal::StaleOrSubstitutedSnapshot)
    );
    assert_eq!(
        model, before_publish,
        "stale snapshot cannot authorize effects"
    );
}

#[test]
fn injected_publication_failures_are_explicitly_unresolved() {
    let make = || {
        let mut model = Model::new(1);
        model.add_fixture_block(1, None, false, 9, None).unwrap();
        model
    };

    let mut after_queue = make();
    let plan = after_queue
        .plan(candidate(2, None), FixtureLimits::TEST)
        .unwrap();
    let result = after_queue.publish(plan, Some(PublishFault::AfterQueueEdit));
    let PublishOutcome::Unresolved(report) = result else {
        panic!("injected queue-edit failure must be unresolved");
    };
    assert_eq!(report.phase, PublicationPhase::AfterQueueEdit);
    assert_eq!(report.queue, E::Observed);
    assert_eq!(report.evictions, E::NotObserved);
    assert!(report.unresolved);
    assert!(after_queue.blocks.contains_key(&1));
    assert!(!after_queue.blocks.contains_key(&2));
    assert!(after_queue.queue.is_empty());

    let mut after_remove = make();
    let plan = after_remove
        .plan(candidate(2, None), FixtureLimits::TEST)
        .unwrap();
    let result = after_remove.publish(plan, Some(PublishFault::AfterFirstVictimRemoval));
    let PublishOutcome::Unresolved(report) = result else {
        panic!("injected removal failure must be unresolved");
    };
    assert_eq!(report.phase, PublicationPhase::AfterVictimRemoval);
    assert_eq!(report.evictions, E::KnownDetailsUnavailable);
    assert_eq!(report.local_accounting, E::KnownDetailsUnavailable);
    assert_eq!(report.known_victims, vec![1]);
    assert!(!after_remove.blocks.contains_key(&1));
    assert!(!after_remove.blocks.contains_key(&2));

    let mut after_registration = make();
    let plan = after_registration
        .plan(candidate(2, None), FixtureLimits::TEST)
        .unwrap();
    let result = after_registration.publish(plan, Some(PublishFault::AfterRegistration));
    let PublishOutcome::Unresolved(report) = result else {
        panic!("injected post-registration failure must be unresolved");
    };
    assert_eq!(report.phase, PublicationPhase::AfterRegistration);
    assert_eq!(report.registration, E::Observed);
    assert!(report.unresolved);
    assert!(after_registration.blocks.contains_key(&2));
}

#[test]
fn bounded_outcomes_preserve_prefix_and_distinguish_unknown_from_no_effect() {
    let mut empty_refusal = model::OutcomeReport::new(FixtureLimits::TEST);
    assert!(empty_refusal.refuse_current(9, ItemPhase::BeforeMutation, true));
    assert_eq!(empty_refusal.terminal, Terminal::NoEffectRefusal);
    assert!(!empty_refusal.unresolved);
    assert!(!empty_refusal.participation_allowed());
    assert!(empty_refusal
        .current
        .unwrap()
        .effects
        .iter()
        .all(|e| *e == E::ConfirmedNoEffect));

    let mut prefix = model::OutcomeReport::new(FixtureLimits::TEST);
    assert!(prefix.record_completed(
        1,
        &[
            VoteDisposition::Added,
            VoteDisposition::Duplicate,
            VoteDisposition::Equivocation,
            VoteDisposition::CapacityDropped,
        ],
        Some(false),
        [E::Observed, E::NotObserved, E::NotObserved, E::NotObserved],
    ));
    assert!(prefix.refuse_current(2, ItemPhase::BeforeMutation, true));
    assert_eq!(prefix.terminal, Terminal::PrefixThenRefusal);
    assert!(prefix.unresolved);
    assert!(!prefix.participation_allowed());
    let completed = &prefix.completed_prefix[0];
    assert_eq!(completed.signer_dispositions.len(), 4);
    assert_eq!(completed.qc_formed, Some(false));
    assert_eq!(
        prefix.current.as_ref().unwrap().effects,
        [E::ConfirmedNoEffect; 4]
    );

    let mut current = model::OutcomeReport::new(FixtureLimits::TEST);
    assert!(current.record_current_failure(
        7,
        ItemPhase::ReplayingSigners { completed: 1 },
        [
            E::KnownDetailsUnavailable,
            E::NotObserved,
            E::NotObserved,
            E::NotObserved,
        ],
    ));
    assert_eq!(current.terminal, Terminal::PartialCurrentItem);
    assert!(current.unresolved);
    assert_eq!(
        current.current.as_ref().unwrap().effects[0],
        E::KnownDetailsUnavailable
    );
    current.mark_complete();
    assert_eq!(current.terminal, Terminal::PartialCurrentItem);
    assert!(!current.participation_allowed());

    let mut complete = model::OutcomeReport::new(FixtureLimits::TEST);
    assert!(complete.record_completed(3, &[VoteDisposition::Duplicate], None, [E::NotObserved; 4]));
    complete.mark_complete();
    assert_eq!(complete.terminal, Terminal::Complete);
    assert!(
        !complete.participation_allowed(),
        "Complete cannot clear quarantine"
    );

    let mut registered = model::OutcomeReport::new(FixtureLimits::TEST);
    assert!(registered.record_current_failure(
        8,
        ItemPhase::Registered,
        [E::Observed, E::NotObserved, E::NotObserved, E::NotObserved],
    ));
    assert_eq!(
        registered.current.as_ref().unwrap().phase,
        ItemPhase::Registered
    );
}

#[test]
fn evidence_limits_and_conflicts_preserve_unresolved_ownership() {
    let tight_limits = FixtureLimits {
        max_input_items: 1,
        max_signers_per_item: 1,
        max_prefix_effect_observations: 1,
        max_late_conflicting_evidence: 1,
        ..FixtureLimits::TEST
    };
    let mut report = model::OutcomeReport::new(tight_limits);
    assert!(!report.record_completed(
        1,
        &[VoteDisposition::Added, VoteDisposition::Duplicate],
        None,
        [E::NotObserved; 4],
    ));
    assert_eq!(report.terminal, Terminal::EvidenceLimitExhausted);
    assert!(report.unresolved);
    assert_eq!(
        report.known_unrecorded_effects, 0,
        "exhaustion without an observed effect must not invent one"
    );
    assert!(!report.participation_allowed());

    let mut effects_limited = model::OutcomeReport::new(tight_limits);
    assert!(!effects_limited.record_completed(
        1,
        &[VoteDisposition::Added],
        Some(true),
        [
            E::Observed,
            E::KnownDetailsUnavailable,
            E::NotObserved,
            E::NotObserved
        ],
    ));
    assert!(effects_limited.unresolved);
    assert_eq!(effects_limited.terminal, Terminal::EvidenceLimitExhausted);
    assert_eq!(effects_limited.known_unrecorded_effects, 2);

    let conflict_limits = FixtureLimits {
        max_late_conflicting_evidence: 2,
        ..tight_limits
    };
    let mut conflicting = model::OutcomeReport::new(conflict_limits);
    assert!(conflicting.record_late_evidence(LateEvidence {
        item_index: 0,
        id: 5,
        kind: EvidenceKind::Late,
    }));
    assert!(conflicting.record_late_evidence(LateEvidence {
        item_index: 0,
        id: 6,
        kind: EvidenceKind::Conflicting,
    }));
    assert_eq!(conflicting.terminal, Terminal::InProgress);
    assert!(conflicting.unresolved);
    assert!(!conflicting.participation_allowed());
    assert!(!conflicting.record_late_evidence(LateEvidence {
        item_index: 1,
        id: 7,
        kind: EvidenceKind::Late,
    }));
    assert_eq!(conflicting.terminal, Terminal::EvidenceLimitExhausted);
    assert!(conflicting.unresolved);
    assert_eq!(conflicting.known_unrecorded_effects, 0);
    assert!(!conflicting.participation_allowed());

    let mut item_limited = model::OutcomeReport::new(FixtureLimits {
        max_input_items: 1,
        ..FixtureLimits::TEST
    });
    assert!(item_limited.record_completed(
        1,
        &[VoteDisposition::Duplicate],
        None,
        [E::NotObserved; 4],
    ));
    assert!(!item_limited.record_completed(
        2,
        &[VoteDisposition::Duplicate],
        None,
        [E::Observed, E::NotObserved, E::NotObserved, E::NotObserved],
    ));
    assert_eq!(item_limited.terminal, Terminal::EvidenceLimitExhausted);
    assert_eq!(item_limited.known_unrecorded_effects, 1);
    assert!(item_limited.unresolved);
}
