//! Opt-in, borrowed test facade. Tokens and reports retain their private owners.
//! No unchecked evidence construction or mutable context access is exposed.

use super::*;
use crate::received_vote_evidence::{SnapshotMember, VoteContextInput};
use qbind_wire::consensus::Vote;
use qbind_wire::pv_signing_domain::ProposalVoteSigningDomainV2;

pub struct Token(VerifiedVoteToken);
impl Token {
    pub fn vote(&self) -> &Vote {
        self.0.vote()
    }
}

pub struct Refusal(ReceivedVoteQcRefusal);
impl Refusal {
    pub fn vote(&self) -> &Vote {
        self.0.token.vote()
    }
    pub fn into_token(self) -> Token {
        Token(self.0.token)
    }
    pub fn preparation_pressure(&self) -> bool {
        matches!(self.0.reason, ReceivedVoteQcRefusalReason::Stage(_))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Application {
    NotAttempted,
    Suppressed,
    Refused,
    Applied,
    Failed,
}

pub struct Report(ReceivedVoteQcReport);
impl Report {
    pub fn wire(&self) -> Option<&qbind_wire::consensus::QuorumCertificate> {
        match self.0.outcome() {
            ReceivedVoteQcOutcome::Complete(wire) => Some(wire.qc()),
            _ => None,
        }
    }
    pub fn incomplete(&self) -> bool {
        matches!(self.0.outcome(), ReceivedVoteQcOutcome::Incomplete(_))
    }
    pub fn application(&self) -> Application {
        match &self.0.actual().application {
            ReceivedQcApplication::NotAttempted => Application::NotAttempted,
            ReceivedQcApplication::Suppressed(_) => Application::Suppressed,
            ReceivedQcApplication::Refused(_) => Application::Refused,
            ReceivedQcApplication::Attempted(Ok(())) => Application::Applied,
            ReceivedQcApplication::Attempted(Err(_)) => Application::Failed,
            ReceivedQcApplication::Ungated => panic!("facade always gates QC effects"),
        }
    }
    pub fn duplicate(&self) -> bool {
        self.0.actual().history == VoteHistoryOutcome::DuplicateSameBlock
    }
    pub fn retained(&self) -> bool {
        self.0.actual().evidence == ReceivedVoteEvidenceDisposition::Retained
    }
    pub fn first_retained_conflict(&self) -> bool {
        self.0.actual().evidence == ReceivedVoteEvidenceDisposition::ExistingSignedFieldsConflict
    }
    pub fn view_advanced(&self) -> bool {
        self.0.actual().view_advanced
    }
    pub fn logical_quorum(&self) -> bool {
        self.0.actual().qc.is_some()
    }
    pub fn charges(&self) -> (u64, u64) {
        let p = match self.0.outcome() {
            ReceivedVoteQcOutcome::Complete(wire) => wire.bytes_charge_for_test(),
            _ => 0,
        };
        (self.0.report_charge_for_test(), p)
    }
}

pub struct Input<'a>(ReceivedQcEffectView<'a>);
impl Input<'_> {
    pub fn wire(&self) -> &qbind_wire::consensus::QuorumCertificate {
        self.0.wire()
    }
    pub fn logical(&self) -> &QuorumCertificate<[u8; 32]> {
        self.0.logical()
    }
    pub fn lock(&self) -> Option<([u8; 32], u64)> {
        self.0.locked().map(|q| (q.block_id, q.view))
    }
    pub fn target_has_qc(&self) -> bool {
        self.0.target_own_qc().is_some()
    }
    pub fn committed(&self) -> Option<([u8; 32], u64)> {
        self.0
            .committed_block()
            .copied()
            .zip(self.0.committed_height())
    }
    pub fn current_view(&self) -> u64 {
        self.0.current_view()
    }
}

struct Gate<'a, F>(&'a mut F);
impl<F: FnMut(Input<'_>) -> bool> ReceivedQcEffectGate for Gate<'_, F> {
    fn evaluate(&mut self, input: ReceivedQcEffectView<'_>) -> ReceivedQcGateDecision {
        if (self.0)(Input(input)) {
            ReceivedQcGateDecision::Allow
        } else {
            ReceivedQcGateDecision::Refuse(ReceivedQcGateRefusal::PublicationUnavailable)
        }
    }
}

pub fn invoke(
    engine: &mut BasicHotStuffEngine<[u8; 32]>,
    token: Token,
    gate: &mut impl FnMut(Input<'_>) -> bool,
) -> Result<Report, Refusal> {
    engine
        .invoke_verified_received_vote_qc_effect_gated(token.0, &mut Gate(gate))
        .map(Report)
        .map_err(Refusal)
}

pub fn admit(
    engine: &mut BasicHotStuffEngine<[u8; 32]>,
    from: ValidatorId,
    vote: Vote,
) -> Result<Token, &'static str> {
    engine
        .admit_verified_received_vote(from, vote)
        .map(Token)
        .map_err(|_| "Vote admission refused")
}

/// Caller-owned immutable authority fixture; the real context install copies
/// these inputs into its ordinarily charged private snapshot.
pub fn install(
    engine: &mut BasicHotStuffEngine<[u8; 32]>,
    domain: &ProposalVoteSigningDomainV2,
    epoch: u64,
    members: &[(ValidatorId, u64, Vec<u8>); 4],
) {
    let input = VoteContextInput::new(
        domain.runtime_chain_id(),
        epoch,
        qbind_crypto::SUITE_PQ_RESERVED_1,
        domain.clone(),
        members
            .iter()
            .map(|(id, power, key)| {
                SnapshotMember::new(
                    id.as_u64(),
                    *power,
                    key.clone().into_boxed_slice().into_vec(),
                )
            })
            .collect(),
    );
    assert!(
        engine.install_received_vote_context(input).is_ok(),
        "context install refused"
    );
}

pub fn context_matches(
    engine: &BasicHotStuffEngine<[u8; 32]>,
    domain: &ProposalVoteSigningDomainV2,
    epoch: u64,
    members: &[(ValidatorId, u64, Vec<u8>); 4],
) -> bool {
    engine
        .active_received_vote_context
        .as_ref()
        .is_some_and(|active| {
            let (actual_domain, actual_epoch, suite, actual_members) = active.inspect_for_test();
            actual_domain == domain
                && actual_epoch == epoch
                && suite == qbind_crypto::SUITE_PQ_RESERVED_1
                && actual_members.len() == members.len()
                && actual_members
                    .iter()
                    .zip(members)
                    .all(|(a, (id, power, key))| {
                        a.validator_id() == id.as_u64()
                            && a.voting_power() == *power
                            && a.public_key() == key
                            && a.public_key_capacity() == key.len()
                    })
                && active.matches_validators(engine.validators())
        })
}

pub fn register(
    engine: &mut BasicHotStuffEngine<[u8; 32]>,
    id: [u8; 32],
    view: u64,
    parent: Option<[u8; 32]>,
) {
    engine.state.register_block(id, view, parent, None);
}

pub fn applications(engine: &BasicHotStuffEngine<[u8; 32]>) -> usize {
    engine.state.qc_applications_for_test()
}
pub fn application_count() -> usize {
    HotStuffStateEngine::<[u8; 32]>::qc_application_count_for_test()
}

pub fn vote_count(engine: &BasicHotStuffEngine<[u8; 32]>, view: u64, id: &[u8; 32]) -> usize {
    engine.state.vote_count(view, id)
}

pub fn retained_vote(
    engine: &BasicHotStuffEngine<[u8; 32]>,
    view: u64,
    signer: u16,
) -> Option<&Vote> {
    engine
        .state
        .received_vote_evidence_table()?
        .entry_for(view, signer)
        .map(|e| e.vote())
}

pub struct Ledger(EvidenceBudget);
impl Ledger {
    pub fn sample(&self) -> (u64, u64, usize, usize, usize, usize) {
        self.0.full_occupancy_for_test()
    }
}
pub fn ledger(engine: &BasicHotStuffEngine<[u8; 32]>) -> Ledger {
    Ledger(
        engine
            .state
            .received_vote_budget()
            .expect("installed context")
            .try_clone()
            .expect("observer"),
    )
}
pub fn empty_ledger_floor() -> (u64, u64, usize, usize, usize, usize) {
    EvidenceBudget::try_new(u64::MAX, 0)
        .expect("sizing ledger")
        .full_occupancy_for_test()
}
pub fn token_inline_bytes() -> u64 {
    std::mem::size_of::<VerifiedVoteToken>() as u64
}
pub fn set_cap(engine: &mut BasicHotStuffEngine<[u8; 32]>, cap: u64) {
    engine.state.set_max_retained_evidence_bytes(cap);
}

/// Source-sized facade control inventory; no QC backing is cloned here.
pub fn control_bytes() -> u128 {
    (std::mem::size_of::<Input<'static>>()
        + std::mem::size_of::<Token>()
        + std::mem::size_of::<Report>()
        + std::mem::size_of::<Refusal>()
        + std::mem::size_of::<Result<Report, Refusal>>()
        + std::mem::size_of::<&mut dyn FnMut(Input<'_>) -> bool>()) as u128
}
