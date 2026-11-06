//! Isolated test model for the proposed A33-F1 catch-up admission contract.
//! This module is not wired into the engine or a participating caller.

use std::collections::{BTreeMap, BTreeSet};

pub type BlockId = u16;
pub type SharedEvidenceId = u16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixtureLimits {
    pub max_input_items: usize,
    pub max_signers_per_item: usize,
    pub max_victims: usize,
    pub max_lineage_visits: usize,
    pub max_prefix_effect_observations: usize,
    pub max_late_conflicting_evidence: usize,
}

impl FixtureLimits {
    pub const TEST: Self = Self {
        max_input_items: 4,
        max_signers_per_item: 4,
        max_victims: 4,
        max_lineage_visits: 32,
        max_prefix_effect_observations: 8,
        max_late_conflicting_evidence: 2,
    };
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub parent: Option<BlockId>,
    pub own_qc: bool,
    pub local_charge: u64,
    pub shared_evidence: Option<SharedEvidenceId>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Accounting {
    pub local_bytes: u64,
    pub shared_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub id: BlockId,
    pub parent: Option<BlockId>,
    pub local_charge: u64,
    pub shared_evidence: Option<(SharedEvidenceId, u64)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    ExistingId(BlockId),
    MissingRequiredLineage(BlockId),
    CyclicRequiredLineage(BlockId),
    LineageWorkBudgetExhausted,
    ArithmeticOverflow,
    AccountingMismatch,
    CandidateSharedChargeMismatch(SharedEvidenceId),
    VictimPlanLimit { needed: usize, limit: usize },
    InsufficientSafeVictims { needed: usize, found: usize },
    CandidateLineageWouldBeRemoved(BlockId),
    StaleOrSubstitutedSnapshot,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Model {
    pub max_blocks: usize,
    pub blocks: BTreeMap<BlockId, Block>,
    pub committed: Option<BlockId>,
    pub lock: Option<BlockId>,
    pub queue: Vec<BlockId>,
    pub shared_charges: BTreeMap<SharedEvidenceId, u64>,
    pub accounting: Accounting,
    generation: u64,
}

impl Model {
    pub fn new(max_blocks: usize) -> Self {
        Self {
            max_blocks,
            blocks: BTreeMap::new(),
            committed: None,
            lock: None,
            queue: Vec::new(),
            shared_charges: BTreeMap::new(),
            accounting: Accounting::default(),
            generation: 0,
        }
    }

    pub fn add_fixture_block(
        &mut self,
        id: BlockId,
        parent: Option<BlockId>,
        own_qc: bool,
        local_charge: u64,
        shared: Option<(SharedEvidenceId, u64)>,
    ) -> Result<(), Refusal> {
        if self.blocks.contains_key(&id) {
            return Err(Refusal::ExistingId(id));
        }
        let next_local = self
            .accounting
            .local_bytes
            .checked_add(local_charge)
            .ok_or(Refusal::ArithmeticOverflow)?;
        let next_shared = match shared {
            Some((shared_id, charge)) => match self.shared_charges.get(&shared_id) {
                Some(existing) if *existing != charge => {
                    return Err(Refusal::CandidateSharedChargeMismatch(shared_id));
                }
                Some(_) => self.accounting.shared_bytes,
                None => self
                    .accounting
                    .shared_bytes
                    .checked_add(charge)
                    .ok_or(Refusal::ArithmeticOverflow)?,
            },
            None => self.accounting.shared_bytes,
        };
        if let Some((shared_id, charge)) = shared {
            self.shared_charges.entry(shared_id).or_insert(charge);
        }
        self.blocks.insert(
            id,
            Block {
                parent,
                own_qc,
                local_charge,
                shared_evidence: shared.map(|(shared_id, _)| shared_id),
            },
        );
        self.queue.push(id);
        self.accounting = Accounting {
            local_bytes: next_local,
            shared_bytes: next_shared,
        };
        self.bump_generation()?;
        Ok(())
    }

    pub fn set_protected_roots(
        &mut self,
        committed: Option<BlockId>,
        lock: Option<BlockId>,
    ) -> Result<(), Refusal> {
        self.committed = committed;
        self.lock = lock;
        self.bump_generation()
    }

    pub fn set_queue_for_test(&mut self, queue: Vec<BlockId>) -> Result<(), Refusal> {
        self.queue = queue;
        self.bump_generation()
    }

    fn bump_generation(&mut self) -> Result<(), Refusal> {
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(Refusal::ArithmeticOverflow)?;
        Ok(())
    }

    fn accounting_is_consistent(&self) -> Result<(), Refusal> {
        let mut local = 0u64;
        let mut referenced_shared = BTreeMap::new();
        for block in self.blocks.values() {
            local = local
                .checked_add(block.local_charge)
                .ok_or(Refusal::ArithmeticOverflow)?;
            if let Some(shared_id) = block.shared_evidence {
                let charge = *self
                    .shared_charges
                    .get(&shared_id)
                    .ok_or(Refusal::AccountingMismatch)?;
                if referenced_shared
                    .insert(shared_id, charge)
                    .is_some_and(|prior| prior != charge)
                {
                    return Err(Refusal::AccountingMismatch);
                }
            }
        }
        if referenced_shared.len() != self.shared_charges.len()
            || referenced_shared != self.shared_charges
        {
            return Err(Refusal::AccountingMismatch);
        }
        let shared = self.shared_charges.values().try_fold(0u64, |sum, charge| {
            sum.checked_add(*charge).ok_or(Refusal::ArithmeticOverflow)
        })?;
        if self.accounting
            != (Accounting {
                local_bytes: local,
                shared_bytes: shared,
            })
        {
            return Err(Refusal::AccountingMismatch);
        }
        Ok(())
    }

    fn walk_lineage(
        &self,
        start: BlockId,
        protected: &mut BTreeSet<BlockId>,
        work: &mut usize,
        limits: FixtureLimits,
    ) -> Result<(), Refusal> {
        let mut current = Some(start);
        let mut visited = BTreeSet::new();
        while let Some(id) = current {
            if *work >= limits.max_lineage_visits {
                return Err(Refusal::LineageWorkBudgetExhausted);
            }
            *work += 1;
            if !visited.insert(id) {
                return Err(Refusal::CyclicRequiredLineage(id));
            }
            let block = self
                .blocks
                .get(&id)
                .ok_or(Refusal::MissingRequiredLineage(id))?;
            protected.insert(id);
            current = block.parent;
        }
        Ok(())
    }

    fn candidate_lineage(
        &self,
        candidate: &Candidate,
        limits: FixtureLimits,
    ) -> Result<BTreeSet<BlockId>, Refusal> {
        let mut protected = BTreeSet::new();
        let mut work = 0;
        if let Some(parent) = candidate.parent {
            self.walk_lineage(parent, &mut protected, &mut work, limits)?;
        }
        Ok(protected)
    }

    fn all_protected_paths(
        &self,
        candidate: &Candidate,
        limits: FixtureLimits,
    ) -> Result<BTreeSet<BlockId>, Refusal> {
        let mut protected = self.candidate_lineage(candidate, limits)?;
        let mut work = protected.len();
        let mut roots = Vec::new();
        roots.extend(self.committed);
        roots.extend(self.lock);
        roots.extend(
            self.blocks
                .iter()
                .filter_map(|(id, block)| block.own_qc.then_some(*id)),
        );
        for root in roots {
            self.walk_lineage(root, &mut protected, &mut work, limits)?;
        }
        Ok(protected)
    }

    /// Common invariant used by the planner and by the direct-parent-only
    /// negative control. This protects the candidate's full retained lineage.
    pub fn plan_preserves_candidate_lineage(
        &self,
        candidate: &Candidate,
        victims: &[BlockId],
        limits: FixtureLimits,
    ) -> Result<bool, Refusal> {
        let lineage = self.candidate_lineage(candidate, limits)?;
        Ok(!victims.iter().any(|id| lineage.contains(id)))
    }

    pub fn plan(
        &self,
        candidate: Candidate,
        limits: FixtureLimits,
    ) -> Result<AdmissionPlan, Refusal> {
        if self.blocks.contains_key(&candidate.id) {
            return Err(Refusal::ExistingId(candidate.id));
        }
        self.accounting_is_consistent()?;

        // Candidate lineage is required even when D == 0. No unrelated
        // protected or unprotected component is scanned in that case.
        let candidate_lineage = self.candidate_lineage(&candidate, limits)?;
        let needed = self
            .blocks
            .len()
            .checked_add(1)
            .ok_or(Refusal::ArithmeticOverflow)?;
        let deficit = needed.saturating_sub(self.max_blocks);
        if deficit > limits.max_victims {
            return Err(Refusal::VictimPlanLimit {
                needed: deficit,
                limit: limits.max_victims,
            });
        }

        let (victims, protected) = if deficit == 0 {
            (Vec::new(), candidate_lineage)
        } else {
            let protected = self.all_protected_paths(&candidate, limits)?;
            let victims = self.choose_victims(deficit, &protected)?;
            if !self.plan_preserves_candidate_lineage(&candidate, &victims, limits)? {
                let id = victims
                    .iter()
                    .copied()
                    .find(|id| candidate_lineage.contains(id))
                    .unwrap_or(candidate.id);
                return Err(Refusal::CandidateLineageWouldBeRemoved(id));
            }
            (victims, protected)
        };

        let expected_accounting = self.project_accounting(&candidate, &victims)?;
        let mut resulting_queue: Vec<_> = self
            .queue
            .iter()
            .copied()
            .filter(|id| !victims.contains(id))
            .collect();
        resulting_queue.push(candidate.id);

        Ok(AdmissionPlan {
            base_generation: self.generation,
            snapshot: self.clone(),
            candidate,
            deficit,
            victims,
            protected,
            expected_accounting,
            resulting_queue,
            limits,
        })
    }

    fn choose_victims(
        &self,
        deficit: usize,
        protected: &BTreeSet<BlockId>,
    ) -> Result<Vec<BlockId>, Refusal> {
        let mut victims = Vec::with_capacity(deficit);
        let mut seen = BTreeSet::new();
        for id in &self.queue {
            if !seen.insert(*id) || !self.blocks.contains_key(id) || protected.contains(id) {
                continue;
            }
            victims.push(*id);
            if victims.len() == deficit {
                return Ok(victims);
            }
        }
        // Deterministic BTreeMap-key fallback is a synthetic model choice.
        // It is not a production HashMap ordering or legacy queue guarantee.
        for id in self.blocks.keys() {
            if !seen.insert(*id) || protected.contains(id) {
                continue;
            }
            victims.push(*id);
            if victims.len() == deficit {
                return Ok(victims);
            }
        }
        Err(Refusal::InsufficientSafeVictims {
            needed: deficit,
            found: victims.len(),
        })
    }

    fn project_accounting(
        &self,
        candidate: &Candidate,
        victims: &[BlockId],
    ) -> Result<Accounting, Refusal> {
        let mut local = self.accounting.local_bytes;
        let mut shared_owners: BTreeMap<SharedEvidenceId, usize> = BTreeMap::new();
        for block in self.blocks.values() {
            if let Some(shared_id) = block.shared_evidence {
                *shared_owners.entry(shared_id).or_default() += 1;
            }
        }
        let mut shared = self.accounting.shared_bytes;
        for id in victims {
            let block = self.blocks.get(id).ok_or(Refusal::AccountingMismatch)?;
            local = local
                .checked_sub(block.local_charge)
                .ok_or(Refusal::AccountingMismatch)?;
            if let Some(shared_id) = block.shared_evidence {
                let owners = shared_owners
                    .get_mut(&shared_id)
                    .ok_or(Refusal::AccountingMismatch)?;
                *owners = owners.checked_sub(1).ok_or(Refusal::AccountingMismatch)?;
                if *owners == 0 {
                    let charge = *self
                        .shared_charges
                        .get(&shared_id)
                        .ok_or(Refusal::AccountingMismatch)?;
                    shared = shared
                        .checked_sub(charge)
                        .ok_or(Refusal::AccountingMismatch)?;
                }
            }
        }
        local = local
            .checked_add(candidate.local_charge)
            .ok_or(Refusal::ArithmeticOverflow)?;
        if let Some((shared_id, charge)) = candidate.shared_evidence {
            match shared_owners.get(&shared_id).copied().unwrap_or(0) {
                0 => {
                    if self.shared_charges.contains_key(&shared_id)
                        && !victims.iter().any(|id| {
                            self.blocks
                                .get(id)
                                .is_some_and(|block| block.shared_evidence == Some(shared_id))
                        })
                    {
                        return Err(Refusal::AccountingMismatch);
                    }
                    shared = shared
                        .checked_add(charge)
                        .ok_or(Refusal::ArithmeticOverflow)?;
                }
                _ => {
                    let existing = self
                        .shared_charges
                        .get(&shared_id)
                        .ok_or(Refusal::AccountingMismatch)?;
                    if *existing != charge {
                        return Err(Refusal::CandidateSharedChargeMismatch(shared_id));
                    }
                }
            }
        }
        Ok(Accounting {
            local_bytes: local,
            shared_bytes: shared,
        })
    }

    pub fn publish(&mut self, plan: AdmissionPlan, fault: Option<PublishFault>) -> PublishOutcome {
        if self.generation != plan.base_generation || *self != plan.snapshot {
            return PublishOutcome::Refused(Refusal::StaleOrSubstitutedSnapshot);
        }
        let protected = if plan.deficit == 0 {
            self.candidate_lineage(&plan.candidate, plan.limits)
        } else {
            self.all_protected_paths(&plan.candidate, plan.limits)
        };
        let protected = match protected {
            Ok(protected) => protected,
            Err(reason) => return PublishOutcome::Refused(reason),
        };
        if let Err(reason) = self.accounting_is_consistent() {
            return PublishOutcome::Refused(reason);
        }
        if plan.deficit != plan.victims.len()
            || plan.victims.iter().copied().collect::<BTreeSet<_>>().len() != plan.victims.len()
            || protected != plan.protected
            || plan.victims.iter().any(|id| protected.contains(id))
            || !self
                .plan_preserves_candidate_lineage(&plan.candidate, &plan.victims, plan.limits)
                .unwrap_or(false)
        {
            return PublishOutcome::Refused(Refusal::StaleOrSubstitutedSnapshot);
        }

        let victim_set: BTreeSet<_> = plan.victims.iter().copied().collect();
        let before_queue = self.queue.clone();
        self.queue.retain(|id| !victim_set.contains(id));
        let queue_changed = self.queue != before_queue;
        if queue_changed && self.bump_generation().is_err() {
            return PublishOutcome::Unresolved(PartialPublication::queue_only());
        }
        let mut effects = PartialPublication {
            phase: PublicationPhase::AfterQueueEdit,
            queue: if queue_changed {
                EffectObservation::Observed
            } else {
                EffectObservation::ConfirmedNoEffect
            },
            evictions: EffectObservation::NotObserved,
            registration: EffectObservation::NotObserved,
            local_accounting: EffectObservation::NotObserved,
            shared_accounting: EffectObservation::NotObserved,
            known_victims: Vec::new(),
            unresolved: true,
        };
        if fault == Some(PublishFault::AfterQueueEdit) {
            return PublishOutcome::Unresolved(effects);
        }

        for id in &plan.victims {
            let Some(block) = self.blocks.get(id).cloned() else {
                return PublishOutcome::Unresolved(effects);
            };
            let Some(local_after) = self.accounting.local_bytes.checked_sub(block.local_charge)
            else {
                effects.local_accounting = EffectObservation::KnownDetailsUnavailable;
                return PublishOutcome::Unresolved(effects);
            };
            let shared_after = match block.shared_evidence {
                Some(shared_id)
                    if !self.blocks.iter().any(|(other_id, other)| {
                        other_id != id && other.shared_evidence == Some(shared_id)
                    }) =>
                {
                    let Some(charge) = self.shared_charges.get(&shared_id).copied() else {
                        effects.shared_accounting = EffectObservation::KnownDetailsUnavailable;
                        return PublishOutcome::Unresolved(effects);
                    };
                    let Some(after) = self.accounting.shared_bytes.checked_sub(charge) else {
                        effects.shared_accounting = EffectObservation::KnownDetailsUnavailable;
                        return PublishOutcome::Unresolved(effects);
                    };
                    Some((shared_id, after))
                }
                _ => None,
            };
            self.accounting.local_bytes = local_after;
            if let Some((shared_id, shared_bytes)) = shared_after {
                self.accounting.shared_bytes = shared_bytes;
                self.shared_charges.remove(&shared_id);
            }
            self.blocks.remove(id);
            effects.known_victims.push(*id);
            effects.phase = PublicationPhase::AfterVictimRemoval;
            effects.evictions = EffectObservation::Observed;
            effects.local_accounting = EffectObservation::Observed;
            if block.shared_evidence.is_some() {
                effects.shared_accounting = EffectObservation::Observed;
            }
            if self.bump_generation().is_err() {
                return PublishOutcome::Unresolved(effects);
            }
            if fault == Some(PublishFault::AfterFirstVictimRemoval) {
                effects.evictions = EffectObservation::KnownDetailsUnavailable;
                effects.local_accounting = EffectObservation::KnownDetailsUnavailable;
                if block.shared_evidence.is_some() {
                    effects.shared_accounting = EffectObservation::KnownDetailsUnavailable;
                }
                effects.phase = PublicationPhase::AfterVictimRemoval;
                return PublishOutcome::Unresolved(effects);
            }
        }

        let candidate = &plan.candidate;
        if self.blocks.contains_key(&candidate.id) {
            return PublishOutcome::Unresolved(effects);
        }
        let Some(local_after) = self
            .accounting
            .local_bytes
            .checked_add(candidate.local_charge)
        else {
            effects.local_accounting = EffectObservation::KnownDetailsUnavailable;
            return PublishOutcome::Unresolved(effects);
        };
        let shared_after = match candidate.shared_evidence {
            Some((shared_id, charge)) => match self.shared_charges.get(&shared_id) {
                Some(existing) if *existing == charge => None,
                Some(_) => {
                    effects.shared_accounting = EffectObservation::KnownDetailsUnavailable;
                    return PublishOutcome::Unresolved(effects);
                }
                None => match self.accounting.shared_bytes.checked_add(charge) {
                    Some(after) => Some((shared_id, charge, after)),
                    None => {
                        effects.shared_accounting = EffectObservation::KnownDetailsUnavailable;
                        return PublishOutcome::Unresolved(effects);
                    }
                },
            },
            None => None,
        };
        self.blocks.insert(
            candidate.id,
            Block {
                parent: candidate.parent,
                own_qc: false,
                local_charge: candidate.local_charge,
                shared_evidence: candidate.shared_evidence.map(|(id, _)| id),
            },
        );
        self.accounting.local_bytes = local_after;
        effects.registration = EffectObservation::Observed;
        effects.local_accounting = EffectObservation::Observed;
        if let Some((shared_id, charge, after)) = shared_after {
            self.shared_charges.insert(shared_id, charge);
            self.accounting.shared_bytes = after;
            effects.shared_accounting = EffectObservation::Observed;
        }
        self.queue.push(candidate.id);
        effects.queue = EffectObservation::Observed;
        effects.phase = PublicationPhase::AfterRegistration;
        if self.bump_generation().is_err() {
            effects.phase = PublicationPhase::AfterRegistration;
            return PublishOutcome::Unresolved(effects);
        }
        if fault == Some(PublishFault::AfterRegistration) {
            effects.phase = PublicationPhase::AfterRegistration;
            return PublishOutcome::Unresolved(effects);
        }
        if self.accounting != plan.expected_accounting
            || self.queue != plan.resulting_queue
            || self.accounting_is_consistent().is_err()
            || plan.victims.iter().any(|id| self.blocks.contains_key(id))
            || !self.blocks.contains_key(&candidate.id)
        {
            effects.phase = PublicationPhase::PostPublicationRevalidation;
            return PublishOutcome::Unresolved(effects);
        }
        PublishOutcome::Published {
            victims: plan.victims,
            accounting: self.accounting,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionPlan {
    base_generation: u64,
    snapshot: Model,
    candidate: Candidate,
    deficit: usize,
    victims: Vec<BlockId>,
    protected: BTreeSet<BlockId>,
    expected_accounting: Accounting,
    resulting_queue: Vec<BlockId>,
    limits: FixtureLimits,
}

impl AdmissionPlan {
    pub fn deficit(&self) -> usize {
        self.deficit
    }

    pub fn victims(&self) -> &[BlockId] {
        &self.victims
    }

    pub fn protected(&self) -> &BTreeSet<BlockId> {
        &self.protected
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublishFault {
    AfterQueueEdit,
    AfterFirstVictimRemoval,
    AfterRegistration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationPhase {
    AfterQueueEdit,
    AfterVictimRemoval,
    AfterRegistration,
    PostPublicationRevalidation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectObservation {
    NotObserved,
    ConfirmedNoEffect,
    KnownDetailsUnavailable,
    Observed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartialPublication {
    pub phase: PublicationPhase,
    pub queue: EffectObservation,
    pub evictions: EffectObservation,
    pub registration: EffectObservation,
    pub local_accounting: EffectObservation,
    pub shared_accounting: EffectObservation,
    pub known_victims: Vec<BlockId>,
    pub unresolved: bool,
}

impl PartialPublication {
    fn queue_only() -> Self {
        Self {
            phase: PublicationPhase::AfterQueueEdit,
            queue: EffectObservation::KnownDetailsUnavailable,
            evictions: EffectObservation::NotObserved,
            registration: EffectObservation::NotObserved,
            local_accounting: EffectObservation::NotObserved,
            shared_accounting: EffectObservation::NotObserved,
            known_victims: Vec::new(),
            unresolved: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublishOutcome {
    Refused(Refusal),
    Published {
        victims: Vec<BlockId>,
        accounting: Accounting,
    },
    Unresolved(PartialPublication),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoteDisposition {
    Added,
    Duplicate,
    Equivocation,
    CapacityDropped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItemPhase {
    BeforeMutation,
    Registered,
    ReplayingSigners { completed: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Terminal {
    InProgress,
    Complete,
    /// Current item and empty replay prefix only; inspect unresolved/evidence separately.
    NoEffectRefusal,
    PrefixThenRefusal,
    PartialCurrentItem,
    EvidenceLimitExhausted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletedItem {
    pub id: BlockId,
    pub signer_dispositions: Vec<VoteDisposition>,
    pub qc_formed: Option<bool>,
    /// Registration, eviction/accounting, vote replay, and QC/lock/commit.
    pub effects: [EffectObservation; 4],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentItem {
    pub id: BlockId,
    pub phase: ItemPhase,
    /// Registration, eviction/accounting, vote replay, and QC/lock/commit.
    pub effects: [EffectObservation; 4],
    pub input_signers: Vec<u16>,
    pub completed_signers: Vec<SignerObservation>,
    pub interrupted_signer: Option<SignerObservation>,
    pub signer_details_unavailable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignerDisposition {
    pub vote_history: EffectObservation,
    /// None means unavailable/unknown, not proof of no accumulator effect.
    pub accumulator: Option<VoteDisposition>,
    pub qc: EffectObservation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignerObservation {
    pub signer: u16,
    pub disposition: SignerDisposition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceKind {
    Late,
    Conflicting,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LateEvidence {
    pub item_index: usize,
    pub id: BlockId,
    pub kind: EvidenceKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutcomeReport {
    pub completed_prefix: Vec<CompletedItem>,
    pub current: Option<CurrentItem>,
    pub late_evidence: Vec<LateEvidence>,
    pub terminal: Terminal,
    pub unresolved: bool,
    pub known_unrecorded_effects: usize,
    pub external_effects: EffectObservation,
    effect_observations: usize,
    limits: FixtureLimits,
}

impl OutcomeReport {
    pub fn new(limits: FixtureLimits) -> Self {
        Self {
            completed_prefix: Vec::new(),
            current: None,
            late_evidence: Vec::new(),
            terminal: Terminal::InProgress,
            unresolved: false,
            known_unrecorded_effects: 0,
            external_effects: EffectObservation::NotObserved,
            effect_observations: 0,
            limits,
        }
    }

    pub fn participation_allowed(&self) -> bool {
        false
    }

    fn count_effects(effects: &[EffectObservation; 4]) -> usize {
        effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect,
                    EffectObservation::Observed | EffectObservation::KnownDetailsUnavailable
                )
            })
            .count()
    }

    fn exhaust(&mut self, known_effects: usize) {
        self.unresolved = true;
        self.terminal = Terminal::EvidenceLimitExhausted;
        self.known_unrecorded_effects = self.known_unrecorded_effects.saturating_add(known_effects);
    }

    pub fn record_completed(
        &mut self,
        id: BlockId,
        dispositions: &[VoteDisposition],
        qc_formed: Option<bool>,
        effects: [EffectObservation; 4],
    ) -> bool {
        let added_effects = Self::count_effects(&effects);
        if self.terminal != Terminal::InProgress
            || self.completed_prefix.len() >= self.limits.max_input_items
            || dispositions.len() > self.limits.max_signers_per_item
            || self
                .effect_observations
                .checked_add(added_effects)
                .is_none_or(|n| n > self.limits.max_prefix_effect_observations)
        {
            self.exhaust(added_effects);
            return false;
        }
        self.effect_observations += added_effects;
        self.completed_prefix.push(CompletedItem {
            id,
            signer_dispositions: dispositions.to_vec(),
            qc_formed,
            effects,
        });
        true
    }

    pub fn record_current_failure(
        &mut self,
        id: BlockId,
        phase: ItemPhase,
        effects: [EffectObservation; 4],
    ) -> bool {
        if self.terminal != Terminal::InProgress
            || self.completed_prefix.len() >= self.limits.max_input_items
        {
            self.exhaust(Self::count_effects(&effects));
            return false;
        }
        if matches!(
            phase,
            ItemPhase::ReplayingSigners { completed }
                if completed > self.limits.max_signers_per_item
        ) {
            self.exhaust(Self::count_effects(&effects));
            return false;
        }
        let count = Self::count_effects(&effects);
        if self
            .effect_observations
            .checked_add(count)
            .is_none_or(|n| n > self.limits.max_prefix_effect_observations)
        {
            self.exhaust(count);
            return false;
        }
        self.effect_observations += count;
        self.current = Some(CurrentItem {
            id,
            phase,
            effects,
            input_signers: Vec::new(),
            completed_signers: Vec::new(),
            interrupted_signer: None,
            signer_details_unavailable: matches!(phase, ItemPhase::ReplayingSigners { .. }),
        });
        self.terminal = Terminal::PartialCurrentItem;
        self.unresolved = true;
        true
    }

    pub fn record_current_signers(
        &mut self,
        id: BlockId,
        input: &[u16],
        completed: &[SignerDisposition],
        interrupted: Option<SignerDisposition>,
        effects: [EffectObservation; 4],
    ) -> bool {
        if input.len() > self.limits.max_signers_per_item
            || completed.len() > input.len()
            || (interrupted.is_some() && completed.len() >= input.len())
        {
            self.exhaust(Self::count_effects(&effects));
            return false;
        }
        let signer_effects = completed
            .iter()
            .chain(interrupted.iter())
            .map(|s| {
                usize::from(matches!(
                    s.vote_history,
                    EffectObservation::Observed | EffectObservation::KnownDetailsUnavailable
                )) + usize::from(s.accumulator == Some(VoteDisposition::Added))
                    + usize::from(matches!(
                        s.qc,
                        EffectObservation::Observed | EffectObservation::KnownDetailsUnavailable
                    ))
            })
            .sum::<usize>();
        let count = Self::count_effects(&effects);
        if self.terminal != Terminal::InProgress
            || self.completed_prefix.len() >= self.limits.max_input_items
            || self
                .effect_observations
                .checked_add(count)
                .and_then(|n| n.checked_add(signer_effects))
                .is_none_or(|n| n > self.limits.max_prefix_effect_observations)
        {
            self.exhaust(count.saturating_add(signer_effects));
            return false;
        }
        if !self.record_current_failure(
            id,
            ItemPhase::ReplayingSigners {
                completed: completed.len(),
            },
            effects,
        ) {
            return false;
        }
        self.effect_observations += signer_effects;
        let current = self.current.as_mut().expect("current failure was recorded");
        current.input_signers = input.to_vec();
        current.completed_signers = input
            .iter()
            .zip(completed)
            .map(|(signer, disposition)| SignerObservation {
                signer: *signer,
                disposition: *disposition,
            })
            .collect();
        current.interrupted_signer = interrupted.map(|disposition| SignerObservation {
            signer: input[completed.len()],
            disposition,
        });
        current.signer_details_unavailable = false;
        true
    }

    pub fn refuse_current(
        &mut self,
        id: BlockId,
        phase: ItemPhase,
        reason_is_before_mutation: bool,
    ) -> bool {
        if self.terminal != Terminal::InProgress
            || self.completed_prefix.len() >= self.limits.max_input_items
        {
            self.exhaust(0);
            return false;
        }
        let before = reason_is_before_mutation && phase == ItemPhase::BeforeMutation;
        let effects = if before {
            [EffectObservation::ConfirmedNoEffect; 4]
        } else {
            [EffectObservation::NotObserved; 4]
        };
        self.current = Some(CurrentItem {
            id,
            phase,
            effects,
            input_signers: Vec::new(),
            completed_signers: Vec::new(),
            interrupted_signer: None,
            signer_details_unavailable: !before,
        });
        self.unresolved |= !self.completed_prefix.is_empty() || !before;
        self.terminal = if before && self.completed_prefix.is_empty() {
            Terminal::NoEffectRefusal
        } else if before {
            Terminal::PrefixThenRefusal
        } else {
            Terminal::PartialCurrentItem
        };
        true
    }

    pub fn record_late_evidence(&mut self, evidence: LateEvidence) -> bool {
        if self.late_evidence.len() >= self.limits.max_late_conflicting_evidence
            || self.terminal == Terminal::EvidenceLimitExhausted
        {
            self.exhaust(0);
            return false;
        }
        if evidence.kind == EvidenceKind::Conflicting {
            self.unresolved = true;
        }
        self.late_evidence.push(evidence);
        true
    }

    pub fn mark_complete(&mut self) {
        if self.terminal == Terminal::InProgress {
            self.terminal = Terminal::Complete;
            self.unresolved |= matches!(
                self.external_effects,
                EffectObservation::NotObserved | EffectObservation::KnownDetailsUnavailable
            );
        }
    }
}
