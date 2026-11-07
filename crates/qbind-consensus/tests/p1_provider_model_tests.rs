//! Isolated P1 provider-envelope model. Test support only: no production
//! authority, application, signing, quarantine-clear, or resume capability.

use std::cell::RefCell;
use std::rc::{Rc, Weak};

#[path = "support/p1_provider_verifier_handoff.rs"]
mod p1_provider_verifier_handoff;

const CANDIDATE_MAGIC: &[u8; 8] = b"QBP1TEST";
const EVIDENCE_MAGIC: &[u8; 8] = b"QBE1TEST";
const CANDIDATE_HEADER: usize = 12;
const EVIDENCE_HEADER: usize = 13;
const MAX_CANDIDATE: usize = 16_384;
const MAX_EVIDENCE: usize = 19_389;
const MAX_COMBINED: usize = 35_773;
const MAX_MEMBERS: usize = 8;
const KEY_BYTES: usize = 1_312;
const MAX_CONTENT: usize = 256;
const MAX_EVIDENCE_ENTRIES: usize = 8;
const MAX_ENTRY_BYTES: usize = 2_420;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Member {
    identity: [u8; 32],
    public_key: Vec<u8>,
    weight: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Candidate {
    network: [u8; 32],
    genesis: [u8; 32],
    purpose: u16,
    schema_version: u16,
    epoch: u64,
    applicability: [u64; 2],
    authority: [u8; 32],
    provenance_source: Vec<u8>,
    policy_version: u16,
    members: Vec<Member>,
    threshold: u64,
    content: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExpectedCatalogFixture {
    identity: u64,
    context: Candidate,
}

impl ExpectedCatalogFixture {
    fn new() -> Self {
        Self::with_identity(1)
    }

    fn with_identity(identity: u64) -> Self {
        Self {
            identity,
            context: valid_candidate(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Currentness {
    Available,
    Unavailable,
    Stale,
    Conflict,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    CandidateTooLarge,
    EvidenceTooLarge,
    CombinedTooLarge,
    LengthOverflow,
    DescriptorMismatch,
    Malformed,
    Unsupported,
    FieldLimitExceeded,
    MemberLimitExceeded,
    EvidenceEntryCountInvalid,
    EvidenceEntryCountExceeded,
    EvidenceEntryLengthInvalid,
    EvidenceEntryTooLarge,
    AmbiguousIdentity,
    AmbiguousKey,
    InvalidWeightOrThreshold,
    ContextMismatch(&'static str),
    CurrentnessUnavailable,
    StaleContext,
    ConflictingContext,
    CurrentnessUnknown,
    LeaseHeld,
    IdentityExhausted,
    LeaseExhausted,
    ProviderReplaced,
    ProviderDestroyed,
    FixtureMismatch,
    InvalidatedBeforeUse,
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
struct Trace {
    descriptor_size_checks: usize,
    materializers: usize,
    actual_size_checks: usize,
    borrowed_scans: usize,
    candidate_frame_checks: usize,
    candidate_field_checks: usize,
    candidate_member_count_checks: usize,
    candidate_member_length_checks: usize,
    evidence_decoder_calls: usize,
    candidate_decoder_calls: usize,
    evidence_outer_size_checks: usize,
    evidence_frame_checks: usize,
    evidence_count_checks: usize,
    evidence_entry_length_checks: usize,
    decoders: usize,
    structural_checks: usize,
    uniqueness_checks: usize,
    context_comparisons: usize,
    admissions: usize,
    currentness_checks: usize,
    provider_identity_checks: usize,
    fixture_binding_checks: usize,
    lease_identity_checks: usize,
    liveness_checks: usize,
    sentinel_effects: usize,
    crypto_calls: usize,
}

#[derive(Clone, Copy)]
struct Descriptor {
    candidate_len: usize,
    evidence_len: usize,
}

struct ProviderInstance {
    identity: u64,
    fixture: ExpectedCatalogFixture,
}

struct LeaseRecord {
    instance_identity: u64,
    lease_identity: u64,
    fixture_identity: u64,
    snapshot: Candidate,
    logical_charge: usize,
}

#[derive(Default)]
struct SlotState {
    next_instance_identity: u64,
    next_lease_identity: u64,
    current: Option<ProviderInstance>,
    lease: Option<LeaseRecord>,
}

struct ProviderSlot {
    state: Rc<RefCell<SlotState>>,
    trace: Rc<RefCell<Trace>>,
}

struct AdmittedTestContext {
    slot: Weak<RefCell<SlotState>>,
    instance_identity: u64,
    lease_identity: u64,
    fixture_identity: u64,
    released: bool,
}

impl ProviderSlot {
    fn new(fixture: &ExpectedCatalogFixture) -> Self {
        let current = ProviderInstance {
            identity: 1,
            fixture: fixture.clone(),
        };
        Self {
            state: Rc::new(RefCell::new(SlotState {
                next_instance_identity: 2,
                next_lease_identity: 1,
                current: Some(current),
                lease: None,
            })),
            trace: Rc::new(RefCell::new(Trace::default())),
        }
    }

    fn trace(&self) -> Trace {
        self.trace.borrow().clone()
    }

    fn logical_charge(&self) -> usize {
        self.state
            .borrow()
            .lease
            .as_ref()
            .map_or(0, |lease| lease.logical_charge)
    }

    fn fixture_logical_charge(&self) -> Result<Option<usize>, Refusal> {
        self.state
            .borrow()
            .current
            .as_ref()
            .map(|current| {
                logical_snapshot_charge(&current.fixture.context)?
                    .checked_add(std::mem::size_of::<u64>())
                    .ok_or(Refusal::LengthOverflow)
            })
            .transpose()
    }

    fn has_lease(&self) -> bool {
        self.state.borrow().lease.is_some()
    }

    fn set_next_identities_for_test(&self, instance: u64, lease: u64) {
        let mut state = self.state.borrow_mut();
        state.next_instance_identity = instance;
        state.next_lease_identity = lease;
    }

    fn replace_current(&self, fixture: &ExpectedCatalogFixture) -> Result<u64, Refusal> {
        let mut state = self.state.borrow_mut();
        let identity = state.next_instance_identity;
        let next = identity.checked_add(1).ok_or(Refusal::IdentityExhausted)?;
        state.next_instance_identity = next;
        state.lease = None;
        state.current = Some(ProviderInstance {
            identity,
            fixture: fixture.clone(),
        });
        Ok(identity)
    }

    fn destroy_current(&self) {
        let mut state = self.state.borrow_mut();
        state.current = None;
        state.lease = None;
    }

    fn admit_decoded(
        &self,
        fixture: &ExpectedCatalogFixture,
        candidate: Candidate,
        currentness: Currentness,
    ) -> Result<AdmittedTestContext, Refusal> {
        self.ensure_admission_available(fixture)?;
        validate_candidate(&candidate, &self.trace)?;
        {
            let state = self.state.borrow();
            let current = state.current.as_ref().ok_or(Refusal::ProviderDestroyed)?;
            compare_context(&current.fixture, &candidate, &self.trace)?;
        }
        require_currentness(currentness, &self.trace)?;

        let charge = logical_snapshot_charge(&candidate)?;
        let mut state = self.state.borrow_mut();
        let current = state.current.as_ref().ok_or(Refusal::ProviderDestroyed)?;
        let instance_identity = current.identity;
        if current.fixture != *fixture {
            return Err(Refusal::FixtureMismatch);
        }
        let lease_identity = state.next_lease_identity;
        let next_lease_identity = lease_identity
            .checked_add(1)
            .ok_or(Refusal::LeaseExhausted)?;
        state.next_lease_identity = next_lease_identity;
        state.lease = Some(LeaseRecord {
            instance_identity,
            lease_identity,
            fixture_identity: fixture.identity,
            snapshot: candidate,
            logical_charge: charge,
        });
        self.trace.borrow_mut().admissions += 1;
        Ok(AdmittedTestContext {
            slot: Rc::downgrade(&self.state),
            instance_identity,
            lease_identity,
            fixture_identity: fixture.identity,
            released: false,
        })
    }

    fn admit_borrowed(
        &self,
        fixture: &ExpectedCatalogFixture,
        candidate_bytes: &[u8],
        evidence_bytes: &[u8],
        currentness: Currentness,
    ) -> Result<AdmittedTestContext, Refusal> {
        self.ensure_admission_available(fixture)?;
        let candidate = scan_borrowed(candidate_bytes, evidence_bytes, &self.trace)?;
        self.admit_decoded(fixture, candidate, currentness)
    }

    fn admit_descriptor<F>(
        &self,
        fixture: &ExpectedCatalogFixture,
        descriptor: Descriptor,
        materialize: F,
        currentness: Currentness,
    ) -> Result<AdmittedTestContext, Refusal>
    where
        F: FnOnce() -> (Vec<u8>, Vec<u8>),
    {
        self.ensure_admission_available(fixture)?;
        descriptor_size_gate(descriptor, &self.trace)?;
        self.trace.borrow_mut().materializers += 1;
        let (candidate, evidence) = materialize();
        self.trace.borrow_mut().actual_size_checks += 1;
        check_actual_size(candidate.len(), evidence.len())?;
        if candidate.len() != descriptor.candidate_len || evidence.len() != descriptor.evidence_len
        {
            return Err(Refusal::DescriptorMismatch);
        }
        let candidate = scan_borrowed(&candidate, &evidence, &self.trace)?;
        self.admit_decoded(fixture, candidate, currentness)
    }

    fn ensure_admission_available(&self, fixture: &ExpectedCatalogFixture) -> Result<(), Refusal> {
        let state = self.state.borrow();
        if state.lease.is_some() {
            return Err(Refusal::LeaseHeld);
        }
        let current = state.current.as_ref().ok_or(Refusal::ProviderDestroyed)?;
        self.trace.borrow_mut().fixture_binding_checks += 1;
        if current.fixture != *fixture {
            return Err(Refusal::FixtureMismatch);
        }
        Ok(())
    }

    fn verify_use<F>(
        &self,
        fixture: &ExpectedCatalogFixture,
        admitted: &AdmittedTestContext,
        currentness: Currentness,
        evidence_bytes: &[u8],
        callback: F,
    ) -> Result<(), Refusal>
    where
        F: FnOnce(&Candidate),
    {
        let state_rc = admitted.slot.upgrade().ok_or(Refusal::ProviderDestroyed)?;
        if !Rc::ptr_eq(&state_rc, &self.state) {
            return Err(Refusal::ProviderReplaced);
        }
        self.trace.borrow_mut().liveness_checks += 1;
        let state = state_rc.borrow();
        let current = state.current.as_ref().ok_or(Refusal::ProviderDestroyed)?;
        self.trace.borrow_mut().provider_identity_checks += 1;
        if current.identity != admitted.instance_identity {
            return Err(Refusal::ProviderReplaced);
        }
        self.trace.borrow_mut().fixture_binding_checks += 1;
        if current.fixture != *fixture || fixture.identity != admitted.fixture_identity {
            return Err(Refusal::FixtureMismatch);
        }
        self.trace.borrow_mut().lease_identity_checks += 1;
        let lease = state.lease.as_ref().ok_or(Refusal::InvalidatedBeforeUse)?;
        if lease.instance_identity != admitted.instance_identity
            || lease.lease_identity != admitted.lease_identity
            || lease.fixture_identity != fixture.identity
        {
            return Err(Refusal::InvalidatedBeforeUse);
        }
        require_currentness(currentness, &self.trace)?;
        scan_evidence(evidence_bytes, 0, &self.trace)?;
        self.trace.borrow_mut().sentinel_effects += 1;
        callback(&lease.snapshot);
        Ok(())
    }
}

impl Drop for AdmittedTestContext {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        if let Some(slot) = self.slot.upgrade() {
            let mut state = slot.borrow_mut();
            let matches = state.lease.as_ref().is_some_and(|lease| {
                lease.instance_identity == self.instance_identity
                    && lease.lease_identity == self.lease_identity
                    && lease.fixture_identity == self.fixture_identity
            });
            if matches {
                state.lease = None;
            }
        }
        self.released = true;
    }
}

fn require_currentness(
    currentness: Currentness,
    trace: &Rc<RefCell<Trace>>,
) -> Result<(), Refusal> {
    trace.borrow_mut().currentness_checks += 1;
    match currentness {
        Currentness::Available => Ok(()),
        Currentness::Unavailable => Err(Refusal::CurrentnessUnavailable),
        Currentness::Stale => Err(Refusal::StaleContext),
        Currentness::Conflict => Err(Refusal::ConflictingContext),
        Currentness::Unknown => Err(Refusal::CurrentnessUnknown),
    }
}

fn validate_candidate(candidate: &Candidate, trace: &Rc<RefCell<Trace>>) -> Result<(), Refusal> {
    trace.borrow_mut().structural_checks += 1;
    if candidate.provenance_source.is_empty() || candidate.provenance_source.len() > 32 {
        return Err(Refusal::FieldLimitExceeded);
    }
    if candidate.content.len() > MAX_CONTENT {
        return Err(Refusal::FieldLimitExceeded);
    }
    if candidate.members.is_empty() || candidate.members.len() > MAX_MEMBERS {
        return Err(Refusal::MemberLimitExceeded);
    }
    check_unique_members(&candidate.members, trace)?;
    let mut total = 0u64;
    for member in &candidate.members {
        if member.public_key.len() != KEY_BYTES || member.weight == 0 {
            return Err(Refusal::InvalidWeightOrThreshold);
        }
        total = total
            .checked_add(member.weight)
            .ok_or(Refusal::InvalidWeightOrThreshold)?;
    }
    if candidate.threshold == 0 || candidate.threshold > total {
        return Err(Refusal::InvalidWeightOrThreshold);
    }
    if candidate.applicability[0] > candidate.applicability[1] {
        return Err(Refusal::FieldLimitExceeded);
    }
    Ok(())
}

fn check_unique_members(members: &[Member], trace: &Rc<RefCell<Trace>>) -> Result<(), Refusal> {
    trace.borrow_mut().uniqueness_checks += 1;
    for (index, member) in members.iter().enumerate() {
        for previous in &members[..index] {
            if previous.identity == member.identity {
                return Err(Refusal::AmbiguousIdentity);
            }
            if previous.public_key == member.public_key {
                return Err(Refusal::AmbiguousKey);
            }
        }
    }
    Ok(())
}

fn strict_uniqueness_stage(
    candidate: &Candidate,
    trace: &Rc<RefCell<Trace>>,
) -> Result<(), Refusal> {
    check_unique_members(&candidate.members, trace)
}

fn omitted_uniqueness_mutant(
    candidate: &Candidate,
    trace: &Rc<RefCell<Trace>>,
) -> Result<(), Refusal> {
    trace.borrow_mut().structural_checks += 1;
    if candidate.members.len() > MAX_MEMBERS {
        return Err(Refusal::MemberLimitExceeded);
    }
    Ok(())
}

fn trust_candidate_context_mutant(_candidate: &Candidate) -> Result<(), Refusal> {
    Ok(())
}

fn compare_without_policy_version_mutant(
    fixture: &ExpectedCatalogFixture,
    candidate: &Candidate,
) -> Result<(), Refusal> {
    let mut projected = candidate.clone();
    projected.policy_version = fixture.context.policy_version;
    if projected == fixture.context {
        Ok(())
    } else {
        Err(Refusal::ContextMismatch("other fields"))
    }
}

fn omitted_currentness_mutant(
    currentness: Currentness,
    trace: &Rc<RefCell<Trace>>,
) -> Result<(), Refusal> {
    let _unconsulted_state = currentness;
    trace.borrow_mut().sentinel_effects += 1;
    Ok(())
}

fn compare_context(
    fixture: &ExpectedCatalogFixture,
    candidate: &Candidate,
    trace: &Rc<RefCell<Trace>>,
) -> Result<(), Refusal> {
    trace.borrow_mut().context_comparisons += 1;
    let expected = &fixture.context;
    let comparisons = [
        (expected.network == candidate.network, "network"),
        (expected.genesis == candidate.genesis, "genesis"),
        (expected.purpose == candidate.purpose, "purpose"),
        (
            expected.schema_version == candidate.schema_version,
            "version",
        ),
        (expected.epoch == candidate.epoch, "epoch"),
        (
            expected.applicability == candidate.applicability,
            "applicability",
        ),
        (expected.authority == candidate.authority, "authority"),
        (
            expected.provenance_source == candidate.provenance_source,
            "provenance",
        ),
        (
            expected.policy_version == candidate.policy_version,
            "policy",
        ),
        (
            expected.members == candidate.members,
            "members/keys/weights",
        ),
        (expected.threshold == candidate.threshold, "threshold"),
        (expected.content == candidate.content, "content"),
    ];
    for (matches, field) in comparisons {
        if !matches {
            return Err(Refusal::ContextMismatch(field));
        }
    }
    Ok(())
}

fn logical_snapshot_charge(candidate: &Candidate) -> Result<usize, Refusal> {
    let mut total = 0usize;
    for size in [
        32usize,
        32,
        2,
        2,
        8,
        16,
        32,
        candidate.provenance_source.len(),
        2,
        8,
        candidate.content.len(),
    ] {
        total = total.checked_add(size).ok_or(Refusal::LengthOverflow)?;
    }
    for member in &candidate.members {
        for size in [32usize, member.public_key.len(), 8] {
            total = total.checked_add(size).ok_or(Refusal::LengthOverflow)?;
        }
    }
    Ok(total)
}

fn descriptor_size_gate(descriptor: Descriptor, trace: &Rc<RefCell<Trace>>) -> Result<(), Refusal> {
    trace.borrow_mut().descriptor_size_checks += 1;
    if descriptor.candidate_len > MAX_CANDIDATE {
        return Err(Refusal::CandidateTooLarge);
    }
    if descriptor.evidence_len > MAX_EVIDENCE {
        return Err(Refusal::EvidenceTooLarge);
    }
    let combined = checked_combined_len(descriptor.candidate_len, descriptor.evidence_len)?;
    if combined > MAX_COMBINED {
        return Err(Refusal::CombinedTooLarge);
    }
    Ok(())
}

fn checked_combined_len(candidate_len: usize, evidence_len: usize) -> Result<usize, Refusal> {
    candidate_len
        .checked_add(evidence_len)
        .ok_or(Refusal::LengthOverflow)
}

fn check_actual_size(candidate_len: usize, evidence_len: usize) -> Result<(), Refusal> {
    if candidate_len > MAX_CANDIDATE {
        return Err(Refusal::CandidateTooLarge);
    }
    if evidence_len > MAX_EVIDENCE {
        return Err(Refusal::EvidenceTooLarge);
    }
    let combined = checked_combined_len(candidate_len, evidence_len)?;
    if combined > MAX_COMBINED {
        return Err(Refusal::CombinedTooLarge);
    }
    Ok(())
}

fn scan_borrowed(
    candidate_bytes: &[u8],
    evidence_bytes: &[u8],
    trace: &Rc<RefCell<Trace>>,
) -> Result<Candidate, Refusal> {
    trace.borrow_mut().borrowed_scans += 1;
    trace.borrow_mut().actual_size_checks += 1;
    check_actual_size(candidate_bytes.len(), evidence_bytes.len())?;
    scan_evidence(evidence_bytes, candidate_bytes.len(), trace)?;
    scan_candidate(candidate_bytes, trace)
}

fn scan_evidence<'a>(
    bytes: &'a [u8],
    candidate_len: usize,
    trace: &Rc<RefCell<Trace>>,
) -> Result<Vec<&'a [u8]>, Refusal> {
    trace.borrow_mut().evidence_outer_size_checks += 1;
    if bytes.len() > MAX_EVIDENCE {
        return Err(Refusal::EvidenceTooLarge);
    }
    let combined = checked_combined_len(candidate_len, bytes.len())?;
    if combined > MAX_COMBINED {
        return Err(Refusal::CombinedTooLarge);
    }
    if bytes.len() < EVIDENCE_HEADER || bytes.get(..8) != Some(EVIDENCE_MAGIC) {
        return Err(Refusal::Malformed);
    }
    let declared_total =
        usize::try_from(read_u32(bytes, 8)?).map_err(|_| Refusal::LengthOverflow)?;
    let count = usize::from(bytes[12]);
    if declared_total != bytes.len() {
        return Err(Refusal::Malformed);
    }
    let mut offset = EVIDENCE_HEADER;
    for _ in 0..count {
        let length = usize::from(read_u16(bytes, offset)?);
        offset = offset.checked_add(2).ok_or(Refusal::LengthOverflow)?;
        let end = offset.checked_add(length).ok_or(Refusal::LengthOverflow)?;
        bytes.get(offset..end).ok_or(Refusal::Malformed)?;
        offset = end;
    }
    if offset != bytes.len() {
        return Err(Refusal::Malformed);
    }
    trace.borrow_mut().evidence_frame_checks += 1;
    trace.borrow_mut().evidence_count_checks += 1;
    if count == 0 {
        return Err(Refusal::EvidenceEntryCountInvalid);
    }
    if count > MAX_EVIDENCE_ENTRIES {
        return Err(Refusal::EvidenceEntryCountExceeded);
    }
    trace.borrow_mut().evidence_entry_length_checks += 1;
    offset = EVIDENCE_HEADER;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let length = usize::from(read_u16(bytes, offset)?);
        if length == 0 {
            return Err(Refusal::EvidenceEntryLengthInvalid);
        }
        if length > MAX_ENTRY_BYTES {
            return Err(Refusal::EvidenceEntryTooLarge);
        }
        let start = offset.checked_add(2).ok_or(Refusal::LengthOverflow)?;
        let end = start.checked_add(length).ok_or(Refusal::LengthOverflow)?;
        entries.push(bytes.get(start..end).ok_or(Refusal::Malformed)?);
        offset = offset
            .checked_add(2)
            .and_then(|start| start.checked_add(length))
            .ok_or(Refusal::LengthOverflow)?;
    }
    trace.borrow_mut().evidence_decoder_calls += 1;
    trace.borrow_mut().decoders += 1;
    Ok(entries)
}

fn scan_candidate(bytes: &[u8], trace: &Rc<RefCell<Trace>>) -> Result<Candidate, Refusal> {
    if bytes.len() < CANDIDATE_HEADER || bytes.get(..8) != Some(CANDIDATE_MAGIC) {
        return Err(Refusal::Malformed);
    }
    if usize::try_from(read_u32(bytes, 8)?).map_err(|_| Refusal::LengthOverflow)? != bytes.len() {
        return Err(Refusal::Malformed);
    }
    let mut offset = CANDIDATE_HEADER;
    let mut fields: Vec<(u16, &[u8])> = Vec::with_capacity(12);
    for expected_tag in 1..=12u16 {
        let tag = read_u16(bytes, offset)?;
        let length_offset = offset.checked_add(2).ok_or(Refusal::LengthOverflow)?;
        let length = usize::try_from(read_u32(bytes, length_offset)?)
            .map_err(|_| Refusal::LengthOverflow)?;
        let value_offset = length_offset
            .checked_add(4)
            .ok_or(Refusal::LengthOverflow)?;
        let end = value_offset
            .checked_add(length)
            .ok_or(Refusal::LengthOverflow)?;
        let value = bytes.get(value_offset..end).ok_or(Refusal::Malformed)?;
        if tag != expected_tag {
            return Err(Refusal::Unsupported);
        }
        fields.push((tag, value));
        offset = end;
    }
    if offset != bytes.len() {
        return Err(Refusal::Malformed);
    }
    trace.borrow_mut().candidate_frame_checks += 1;
    check_candidate_field_shapes(&fields, trace)?;
    scan_member_uniqueness(fields[9].1, trace)?;
    trace.borrow_mut().candidate_decoder_calls += 1;
    trace.borrow_mut().decoders += 1;
    decode_candidate(&fields)
}

fn check_candidate_field_shapes(
    fields: &[(u16, &[u8])],
    trace: &Rc<RefCell<Trace>>,
) -> Result<(), Refusal> {
    trace.borrow_mut().candidate_field_checks += 1;
    let fixed = [
        (0, 32),
        (1, 32),
        (2, 2),
        (3, 2),
        (4, 8),
        (5, 16),
        (6, 32),
        (8, 2),
        (10, 8),
    ];
    if fields.len() != 12
        || fixed
            .iter()
            .any(|(index, len)| fields[*index].1.len() != *len)
    {
        return Err(Refusal::Malformed);
    }
    if fields[7].1.is_empty() || fields[7].1.len() > 32 {
        return Err(Refusal::FieldLimitExceeded);
    }
    if fields[11].1.len() > MAX_CONTENT {
        return Err(Refusal::FieldLimitExceeded);
    }
    Ok(())
}

fn scan_member_uniqueness(bytes: &[u8], trace: &Rc<RefCell<Trace>>) -> Result<(), Refusal> {
    trace.borrow_mut().uniqueness_checks += 1;
    let count = usize::from(*bytes.first().ok_or(Refusal::Malformed)?);
    trace.borrow_mut().candidate_member_count_checks += 1;
    if count == 0 || count > MAX_MEMBERS {
        return Err(Refusal::MemberLimitExceeded);
    }
    let mut offset = 1usize;
    let mut members: Vec<(&[u8], &[u8])> = Vec::with_capacity(count);
    for _ in 0..count {
        trace.borrow_mut().candidate_member_length_checks += 1;
        let identity_end = offset.checked_add(32).ok_or(Refusal::LengthOverflow)?;
        let identity = bytes.get(offset..identity_end).ok_or(Refusal::Malformed)?;
        let key_len = usize::from(read_u16(bytes, identity_end)?);
        if key_len != KEY_BYTES {
            return Err(Refusal::FieldLimitExceeded);
        }
        let key_start = identity_end.checked_add(2).ok_or(Refusal::LengthOverflow)?;
        let key_end = key_start
            .checked_add(key_len)
            .ok_or(Refusal::LengthOverflow)?;
        let key = bytes.get(key_start..key_end).ok_or(Refusal::Malformed)?;
        let end = key_end.checked_add(8).ok_or(Refusal::LengthOverflow)?;
        if bytes.get(key_end..end).is_none() {
            return Err(Refusal::Malformed);
        }
        for (old_identity, old_key) in &members {
            if *old_identity == identity {
                return Err(Refusal::AmbiguousIdentity);
            }
            if *old_key == key {
                return Err(Refusal::AmbiguousKey);
            }
        }
        members.push((identity, key));
        offset = end;
    }
    if offset != bytes.len() {
        return Err(Refusal::Malformed);
    }
    Ok(())
}

fn decode_candidate(fields: &[(u16, &[u8])]) -> Result<Candidate, Refusal> {
    let mut members = Vec::new();
    let member_bytes = fields[9].1;
    let count = usize::from(*member_bytes.first().ok_or(Refusal::Malformed)?);
    let mut offset = 1usize;
    for _ in 0..count {
        let identity_end = offset.checked_add(32).ok_or(Refusal::LengthOverflow)?;
        let identity: [u8; 32] = member_bytes
            .get(offset..identity_end)
            .ok_or(Refusal::Malformed)?
            .try_into()
            .map_err(|_| Refusal::Malformed)?;
        let key_len = usize::from(read_u16(member_bytes, identity_end)?);
        let key_start = identity_end.checked_add(2).ok_or(Refusal::LengthOverflow)?;
        let key_end = key_start
            .checked_add(key_len)
            .ok_or(Refusal::LengthOverflow)?;
        let public_key = member_bytes
            .get(key_start..key_end)
            .ok_or(Refusal::Malformed)?
            .to_vec();
        let weight = read_u64(member_bytes, key_end)?;
        offset = key_end.checked_add(8).ok_or(Refusal::LengthOverflow)?;
        members.push(Member {
            identity,
            public_key,
            weight,
        });
    }
    Ok(Candidate {
        network: fields[0].1.try_into().map_err(|_| Refusal::Malformed)?,
        genesis: fields[1].1.try_into().map_err(|_| Refusal::Malformed)?,
        purpose: read_u16(fields[2].1, 0)?,
        schema_version: read_u16(fields[3].1, 0)?,
        epoch: read_u64(fields[4].1, 0)?,
        applicability: [read_u64(fields[5].1, 0)?, read_u64(fields[5].1, 8)?],
        authority: fields[6].1.try_into().map_err(|_| Refusal::Malformed)?,
        provenance_source: fields[7].1.to_vec(),
        policy_version: read_u16(fields[8].1, 0)?,
        members,
        threshold: read_u64(fields[10].1, 0)?,
        content: fields[11].1.to_vec(),
    })
}

fn encode_candidate(candidate: &Candidate) -> Vec<u8> {
    let mut fields = Vec::with_capacity(12);
    fields.push(candidate.network.to_vec());
    fields.push(candidate.genesis.to_vec());
    fields.push(candidate.purpose.to_le_bytes().to_vec());
    fields.push(candidate.schema_version.to_le_bytes().to_vec());
    fields.push(candidate.epoch.to_le_bytes().to_vec());
    let mut applicability = Vec::with_capacity(16);
    applicability.extend_from_slice(&candidate.applicability[0].to_le_bytes());
    applicability.extend_from_slice(&candidate.applicability[1].to_le_bytes());
    fields.push(applicability);
    fields.push(candidate.authority.to_vec());
    fields.push(candidate.provenance_source.clone());
    fields.push(candidate.policy_version.to_le_bytes().to_vec());
    let mut members = vec![candidate.members.len() as u8];
    for member in &candidate.members {
        members.extend_from_slice(&member.identity);
        members.extend_from_slice(&(member.public_key.len() as u16).to_le_bytes());
        members.extend_from_slice(&member.public_key);
        members.extend_from_slice(&member.weight.to_le_bytes());
    }
    fields.push(members);
    fields.push(candidate.threshold.to_le_bytes().to_vec());
    fields.push(candidate.content.clone());
    let total = CANDIDATE_HEADER + fields.iter().map(|field| 6 + field.len()).sum::<usize>();
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(CANDIDATE_MAGIC);
    bytes.extend_from_slice(&(total as u32).to_le_bytes());
    for (index, field) in fields.into_iter().enumerate() {
        bytes.extend_from_slice(&((index + 1) as u16).to_le_bytes());
        bytes.extend_from_slice(&(field.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&field);
    }
    bytes
}

fn encode_evidence(entries: &[Vec<u8>]) -> Vec<u8> {
    let total = EVIDENCE_HEADER + entries.iter().map(|entry| 2 + entry.len()).sum::<usize>();
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(EVIDENCE_MAGIC);
    bytes.extend_from_slice(&(total as u32).to_le_bytes());
    bytes.push(entries.len() as u8);
    for entry in entries {
        bytes.extend_from_slice(&(entry.len() as u16).to_le_bytes());
        bytes.extend_from_slice(entry);
    }
    bytes
}

fn valid_candidate() -> Candidate {
    Candidate {
        network: [0x10; 32],
        genesis: [0x20; 32],
        purpose: 1,
        schema_version: 1,
        epoch: 7,
        applicability: [0, 10],
        authority: [0x30; 32],
        provenance_source: vec![0x40; 32],
        policy_version: 1,
        members: (1..=8)
            .map(|index| Member {
                identity: [index; 32],
                public_key: vec![0x50 + index; KEY_BYTES],
                weight: 1,
            })
            .collect(),
        threshold: 5,
        content: vec![0x60; MAX_CONTENT],
    }
}

fn valid_evidence() -> Vec<u8> {
    encode_evidence(
        &(1..=8)
            .map(|index| vec![index; MAX_ENTRY_BYTES])
            .collect::<Vec<_>>(),
    )
}

fn minimal_evidence() -> Vec<u8> {
    encode_evidence(&[vec![1]])
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, Refusal> {
    let end = offset.checked_add(2).ok_or(Refusal::LengthOverflow)?;
    let bytes: [u8; 2] = bytes
        .get(offset..end)
        .ok_or(Refusal::Malformed)?
        .try_into()
        .map_err(|_| Refusal::Malformed)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, Refusal> {
    let end = offset.checked_add(4).ok_or(Refusal::LengthOverflow)?;
    let bytes: [u8; 4] = bytes
        .get(offset..end)
        .ok_or(Refusal::Malformed)?
        .try_into()
        .map_err(|_| Refusal::Malformed)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, Refusal> {
    let end = offset.checked_add(8).ok_or(Refusal::LengthOverflow)?;
    let bytes: [u8; 8] = bytes
        .get(offset..end)
        .ok_or(Refusal::Malformed)?
        .try_into()
        .map_err(|_| Refusal::Malformed)?;
    Ok(u64::from_le_bytes(bytes))
}

#[test]
fn independently_supplied_catalog_and_restored_positive_admission() {
    let fixture = ExpectedCatalogFixture::new();
    let original = fixture.context.clone();
    let slot = ProviderSlot::new(&fixture);
    for _ in 0..2 {
        let admitted = slot
            .admit_decoded(&fixture, fixture.context.clone(), Currentness::Available)
            .unwrap();
        slot.verify_use(
            &fixture,
            &admitted,
            Currentness::Available,
            &minimal_evidence(),
            |snapshot| assert_eq!(snapshot, &original),
        )
        .unwrap();
        assert_eq!(
            slot.logical_charge(),
            logical_snapshot_charge(&original).unwrap()
        );
        drop(admitted);
        assert_eq!(slot.logical_charge(), 0);
    }
    let trace = slot.trace();
    assert_eq!(trace.structural_checks, 2);
    assert_eq!(trace.uniqueness_checks, 2);
    assert_eq!(trace.context_comparisons, 2);
    assert_eq!(trace.admissions, 2);
    assert_eq!(trace.candidate_decoder_calls, 0);
    assert_eq!(trace.evidence_decoder_calls, 2);
    assert_eq!(trace.sentinel_effects, 2);
    assert_eq!(trace.crypto_calls, 0);
}

#[test]
fn complete_context_mismatches_refuse_against_unchanged_fixture() {
    let fixture = ExpectedCatalogFixture::new();
    let mutations: [fn(&mut Candidate); 12] = [
        |candidate| candidate.network[0] ^= 1,
        |candidate| candidate.genesis[0] ^= 1,
        |candidate| candidate.purpose += 1,
        |candidate| candidate.schema_version += 1,
        |candidate| candidate.epoch += 1,
        |candidate| candidate.applicability[1] += 1,
        |candidate| candidate.authority[0] ^= 1,
        |candidate| candidate.provenance_source[0] ^= 1,
        |candidate| candidate.policy_version += 1,
        |candidate| candidate.members[0].weight += 1,
        |candidate| candidate.threshold -= 1,
        |candidate| candidate.content[0] ^= 1,
    ];
    for mutate in mutations {
        let slot = ProviderSlot::new(&fixture);
        let mut candidate = fixture.context.clone();
        mutate(&mut candidate);
        assert!(matches!(
            slot.admit_decoded(&fixture, candidate, Currentness::Available),
            Err(Refusal::ContextMismatch(_))
        ));
        assert_eq!(slot.trace().context_comparisons, 1);
        assert_eq!(slot.trace().admissions, 0);
        assert!(!slot.has_lease());
    }
}

#[test]
fn uniqueness_stage_mutants_fail_the_same_strict_oracle() {
    let fixture = ExpectedCatalogFixture::new();
    for duplicate_key in [false, true] {
        let mut malformed = fixture.context.clone();
        if duplicate_key {
            malformed.members[1].public_key = malformed.members[0].public_key.clone();
        } else {
            malformed.members[1].identity = malformed.members[0].identity;
        }
        let strict_trace = Rc::new(RefCell::new(Trace::default()));
        assert_eq!(
            strict_uniqueness_stage(&malformed, &strict_trace),
            Err(if duplicate_key {
                Refusal::AmbiguousKey
            } else {
                Refusal::AmbiguousIdentity
            })
        );
        assert_eq!(strict_trace.borrow().uniqueness_checks, 1);

        let mutant_trace = Rc::new(RefCell::new(Trace::default()));
        let mutant = omitted_uniqueness_mutant(&malformed, &mutant_trace);
        assert!(mutant.is_ok());
        assert_ne!(mutant, strict_uniqueness_stage(&malformed, &strict_trace));

        let slot = ProviderSlot::new(&fixture);
        assert_eq!(
            slot.admit_decoded(&fixture, malformed.clone(), Currentness::Available)
                .err(),
            Some(if duplicate_key {
                Refusal::AmbiguousKey
            } else {
                Refusal::AmbiguousIdentity
            })
        );
        assert_eq!(slot.trace().structural_checks, 1);
        assert_eq!(slot.trace().uniqueness_checks, 1);
        assert_eq!(slot.trace().context_comparisons, 0);
        assert_eq!(slot.trace().admissions, 0);

        let comparison_trace = Rc::new(RefCell::new(Trace::default()));
        assert_eq!(
            compare_context(&fixture, &malformed, &comparison_trace),
            Err(Refusal::ContextMismatch("members/keys/weights"))
        );
        assert_eq!(comparison_trace.borrow().context_comparisons, 1);

        let restored = ProviderSlot::new(&fixture)
            .admit_decoded(&fixture, fixture.context.clone(), Currentness::Available)
            .unwrap();
        drop(restored);
    }
}

#[test]
fn trust_selection_omitted_field_and_currentness_mutants_are_detected() {
    let fixture = ExpectedCatalogFixture::new();
    let mut altered = fixture.context.clone();
    altered.policy_version += 1;
    let strict_trace = Rc::new(RefCell::new(Trace::default()));
    assert_eq!(
        compare_context(&fixture, &altered, &strict_trace),
        Err(Refusal::ContextMismatch("policy"))
    );
    assert_eq!(strict_trace.borrow().context_comparisons, 1);
    assert_eq!(trust_candidate_context_mutant(&altered), Ok(()));
    assert_ne!(
        trust_candidate_context_mutant(&altered),
        compare_context(&fixture, &altered, &strict_trace)
    );
    assert_eq!(
        compare_without_policy_version_mutant(&fixture, &altered),
        Ok(())
    );
    assert_ne!(
        compare_without_policy_version_mutant(&fixture, &altered),
        compare_context(&fixture, &altered, &strict_trace)
    );

    let strict_currentness_trace = Rc::new(RefCell::new(Trace::default()));
    assert_eq!(
        require_currentness(Currentness::Unknown, &strict_currentness_trace),
        Err(Refusal::CurrentnessUnknown)
    );
    let mutant_trace = Rc::new(RefCell::new(Trace::default()));
    assert_eq!(
        omitted_currentness_mutant(Currentness::Unknown, &mutant_trace),
        Ok(())
    );
    assert_eq!(mutant_trace.borrow().sentinel_effects, 1);
    assert_eq!(strict_currentness_trace.borrow().sentinel_effects, 0);
}

#[test]
fn currentness_states_and_rollback_without_independent_observation_refuse() {
    let fixture = ExpectedCatalogFixture::new();
    for (state, expected) in [
        (Currentness::Unavailable, Refusal::CurrentnessUnavailable),
        (Currentness::Stale, Refusal::StaleContext),
        (Currentness::Conflict, Refusal::ConflictingContext),
        (Currentness::Unknown, Refusal::CurrentnessUnknown),
    ] {
        let slot = ProviderSlot::new(&fixture);
        assert_eq!(
            slot.admit_decoded(&fixture, fixture.context.clone(), state)
                .err(),
            Some(expected)
        );
        assert_eq!(slot.trace().context_comparisons, 1);
        assert_eq!(slot.trace().currentness_checks, 1);
        assert_eq!(slot.trace().admissions, 0);
        assert_eq!(slot.trace().sentinel_effects, 0);
    }

    let old_copy = fixture.context.clone();
    let slot = ProviderSlot::new(&fixture);
    assert_eq!(
        slot.admit_decoded(&fixture, old_copy, Currentness::Unknown)
            .err(),
        Some(Refusal::CurrentnessUnknown)
    );
    assert_eq!(slot.trace().sentinel_effects, 0);
}

#[test]
fn provider_slot_rejects_a_different_fixture_identity() {
    let fixture = ExpectedCatalogFixture::new();
    let other_fixture = ExpectedCatalogFixture::with_identity(2);
    let slot = ProviderSlot::new(&fixture);
    assert_eq!(
        slot.admit_decoded(
            &other_fixture,
            other_fixture.context.clone(),
            Currentness::Available
        )
        .err(),
        Some(Refusal::FixtureMismatch)
    );
    assert_eq!(slot.trace().structural_checks, 0);
    assert_eq!(slot.trace().admissions, 0);
}

#[test]
fn p1_impl1_same_id_fixture_substitution_refuses_and_replacement_succeeds() {
    let a = ExpectedCatalogFixture::new();
    for kind in ["policy", "catalog"] {
        let mut b = ExpectedCatalogFixture::with_identity(a.identity);
        match kind {
            "policy" => b.context.policy_version += 1,
            "catalog" => b.context.members[0].weight += 1,
            _ => unreachable!(),
        }
        assert_eq!(a.identity, b.identity);
        assert_ne!(a.context, b.context);
        let trace = Rc::new(RefCell::new(Trace::default()));
        validate_candidate(&a.context, &trace).unwrap();
        validate_candidate(&b.context, &trace).unwrap();
        let slot = ProviderSlot::new(&a);
        let expected_charge = logical_snapshot_charge(&a.context).unwrap() + 8;
        assert_eq!(
            slot.fixture_logical_charge().unwrap(),
            Some(expected_charge)
        );
        assert_eq!(
            slot.admit_decoded(&b, b.context.clone(), Currentness::Available)
                .err(),
            Some(Refusal::FixtureMismatch)
        );
        let t = slot.trace();
        assert_eq!(
            (
                t.fixture_binding_checks,
                t.structural_checks,
                t.context_comparisons,
                t.currentness_checks,
                t.admissions
            ),
            (1, 0, 0, 0, 0)
        );
        assert_eq!(slot.logical_charge(), 0);
        assert_eq!(
            slot.admit_descriptor(
                &b,
                Descriptor {
                    candidate_len: 0,
                    evidence_len: 0,
                },
                || panic!("substituted fixture must not materialize"),
                Currentness::Available,
            )
            .err(),
            Some(Refusal::FixtureMismatch)
        );
        assert_eq!(slot.trace().materializers, 0);
        assert_eq!(
            slot.admit_decoded(&a, b.context.clone(), Currentness::Available)
                .err(),
            Some(Refusal::ContextMismatch(if kind == "policy" {
                "policy"
            } else {
                "members/keys/weights"
            }))
        );
        let t = slot.trace();
        assert_eq!(
            (
                t.fixture_binding_checks,
                t.structural_checks,
                t.uniqueness_checks,
                t.context_comparisons,
                t.admissions
            ),
            (3, 1, 1, 1, 0)
        );
        let admitted = slot
            .admit_decoded(&a, a.context.clone(), Currentness::Available)
            .unwrap();
        assert_eq!(
            slot.fixture_logical_charge().unwrap(),
            Some(expected_charge)
        );
        assert_eq!(
            slot.logical_charge(),
            logical_snapshot_charge(&a.context).unwrap()
        );
        let before = slot.trace();
        assert_eq!(
            slot.verify_use(
                &b,
                &admitted,
                Currentness::Available,
                &minimal_evidence(),
                |_| {}
            ),
            Err(Refusal::FixtureMismatch)
        );
        let after = slot.trace();
        assert_eq!(after.liveness_checks, before.liveness_checks + 1);
        assert_eq!(
            after.provider_identity_checks,
            before.provider_identity_checks + 1
        );
        assert_eq!(
            after.fixture_binding_checks,
            before.fixture_binding_checks + 1
        );
        assert_eq!(after.lease_identity_checks, before.lease_identity_checks);
        assert_eq!(after.currentness_checks, before.currentness_checks);
        assert_eq!(after.evidence_decoder_calls, before.evidence_decoder_calls);
        assert_eq!(after.sentinel_effects, 0);
        slot.verify_use(
            &a,
            &admitted,
            Currentness::Available,
            &minimal_evidence(),
            |snapshot| {
                assert_eq!(snapshot, &a.context);
            },
        )
        .unwrap();
        assert_eq!(slot.trace().sentinel_effects, 1);
        slot.replace_current(&b).unwrap();
        assert_eq!(
            slot.fixture_logical_charge().unwrap(),
            Some(logical_snapshot_charge(&b.context).unwrap() + 8)
        );
        assert_eq!(
            slot.verify_use(
                &b,
                &admitted,
                Currentness::Available,
                &minimal_evidence(),
                |_| {}
            ),
            Err(Refusal::ProviderReplaced)
        );
        let new_lease = slot
            .admit_decoded(&b, b.context.clone(), Currentness::Available)
            .unwrap();
        let charge = slot.logical_charge();
        drop(admitted);
        assert_eq!(slot.logical_charge(), charge);
        slot.verify_use(
            &b,
            &new_lease,
            Currentness::Available,
            &minimal_evidence(),
            |snapshot| {
                assert_eq!(snapshot, &b.context);
            },
        )
        .unwrap();
        drop(new_lease);
        assert_eq!(slot.logical_charge(), 0);
        assert!(slot.fixture_logical_charge().unwrap().is_some());
        slot.destroy_current();
        assert_eq!(slot.fixture_logical_charge().unwrap(), None);
        println!("CORRECTED {kind}: same-ID substitution refused at fixture binding; A and replaced B use succeed");
    }
}

#[test]
fn p1_impl1_bound_fixture_is_immutable_and_exhaustion_preserves_it() {
    let mut supplied = ExpectedCatalogFixture::new();
    let original = supplied.clone();
    let slot = ProviderSlot::new(&supplied);
    supplied.context.policy_version += 1;
    assert_eq!(
        slot.admit_decoded(&supplied, supplied.context.clone(), Currentness::Available)
            .err(),
        Some(Refusal::FixtureMismatch)
    );
    slot.set_next_identities_for_test(u64::MAX, 1);
    assert_eq!(
        slot.replace_current(&supplied),
        Err(Refusal::IdentityExhausted)
    );
    let token = slot
        .admit_decoded(&original, original.context.clone(), Currentness::Available)
        .unwrap();
    slot.verify_use(
        &original,
        &token,
        Currentness::Available,
        &minimal_evidence(),
        |_| {},
    )
    .unwrap();
}

#[test]
fn use_rechecks_independent_currentness_before_sentinel() {
    let fixture = ExpectedCatalogFixture::new();
    let slot = ProviderSlot::new(&fixture);
    let admitted = slot
        .admit_decoded(&fixture, fixture.context.clone(), Currentness::Available)
        .unwrap();
    assert_eq!(
        slot.verify_use(
            &fixture,
            &admitted,
            Currentness::Stale,
            &minimal_evidence(),
            |_| {},
        ),
        Err(Refusal::StaleContext)
    );
    assert_eq!(slot.trace().currentness_checks, 2);
    assert_eq!(slot.trace().sentinel_effects, 0);
    slot.verify_use(
        &fixture,
        &admitted,
        Currentness::Available,
        &minimal_evidence(),
        |_| {},
    )
    .unwrap();
    assert_eq!(slot.trace().sentinel_effects, 1);
}

#[test]
fn each_unavailable_use_currentness_class_refuses_after_admission() {
    let fixture = ExpectedCatalogFixture::new();
    for (state, expected) in [
        (Currentness::Unavailable, Refusal::CurrentnessUnavailable),
        (Currentness::Stale, Refusal::StaleContext),
        (Currentness::Conflict, Refusal::ConflictingContext),
        (Currentness::Unknown, Refusal::CurrentnessUnknown),
    ] {
        let slot = ProviderSlot::new(&fixture);
        let admitted = slot
            .admit_decoded(&fixture, fixture.context.clone(), Currentness::Available)
            .unwrap();
        assert_eq!(
            slot.verify_use(&fixture, &admitted, state, &minimal_evidence(), |_| {}),
            Err(expected)
        );
        assert_eq!(slot.trace().currentness_checks, 2);
        assert_eq!(slot.trace().sentinel_effects, 0);
    }
}

#[test]
fn use_scans_bounded_evidence_before_sentinel() {
    let fixture = ExpectedCatalogFixture::new();
    let slot = ProviderSlot::new(&fixture);
    let admitted = slot
        .admit_decoded(&fixture, fixture.context.clone(), Currentness::Available)
        .unwrap();
    let excessive = encode_evidence(&(1..=9).map(|id| vec![id; 1]).collect::<Vec<_>>());
    assert_eq!(
        slot.verify_use(
            &fixture,
            &admitted,
            Currentness::Available,
            &excessive,
            |_| {},
        ),
        Err(Refusal::EvidenceEntryCountExceeded)
    );
    assert_eq!(slot.trace().sentinel_effects, 0);
    assert_eq!(slot.trace().evidence_decoder_calls, 0);
    assert_eq!(slot.trace().crypto_calls, 0);

    slot.verify_use(
        &fixture,
        &admitted,
        Currentness::Available,
        &minimal_evidence(),
        |_| {},
    )
    .unwrap();
    assert_eq!(slot.trace().sentinel_effects, 1);
    assert_eq!(slot.trace().evidence_decoder_calls, 1);
}

#[test]
fn provider_replacement_destruction_and_lease_release_are_isolated() {
    let fixture = ExpectedCatalogFixture::new();
    let slot = ProviderSlot::new(&fixture);
    let admitted = slot
        .admit_decoded(&fixture, fixture.context.clone(), Currentness::Available)
        .unwrap();
    assert_eq!(
        slot.admit_decoded(&fixture, fixture.context.clone(), Currentness::Available)
            .err(),
        Some(Refusal::LeaseHeld)
    );
    assert_eq!(slot.trace().admissions, 1);
    let old_lease = slot.logical_charge();
    assert!(old_lease > 0);
    let mut materializer_called = false;
    assert_eq!(
        slot.admit_descriptor(
            &fixture,
            Descriptor {
                candidate_len: 11_339,
                evidence_len: 16,
            },
            || {
                materializer_called = true;
                (Vec::new(), Vec::new())
            },
            Currentness::Available,
        )
        .err(),
        Some(Refusal::LeaseHeld)
    );
    assert!(!materializer_called);
    assert_eq!(slot.trace().materializers, 0);
    slot.replace_current(&fixture).unwrap();
    assert_eq!(
        slot.verify_use(
            &fixture,
            &admitted,
            Currentness::Available,
            &minimal_evidence(),
            |_| {},
        ),
        Err(Refusal::ProviderReplaced)
    );
    let second = slot
        .admit_decoded(&fixture, fixture.context.clone(), Currentness::Available)
        .unwrap();
    let second_charge = slot.logical_charge();
    drop(admitted);
    assert_eq!(slot.logical_charge(), second_charge);
    slot.verify_use(
        &fixture,
        &second,
        Currentness::Available,
        &minimal_evidence(),
        |_| {},
    )
    .unwrap();
    slot.destroy_current();
    assert_eq!(
        slot.verify_use(
            &fixture,
            &second,
            Currentness::Available,
            &minimal_evidence(),
            |_| {},
        ),
        Err(Refusal::ProviderDestroyed)
    );
    drop(second);
    assert_eq!(slot.logical_charge(), 0);

    let after_release = slot.replace_current(&fixture).unwrap();
    assert!(after_release > 1);
    let third = slot
        .admit_decoded(&fixture, fixture.context.clone(), Currentness::Available)
        .unwrap();
    assert!(slot.has_lease());
    drop(third);
    assert!(!slot.has_lease());
}

#[test]
fn slot_destruction_and_identity_exhaustion_do_not_reuse_authority_tokens() {
    let fixture = ExpectedCatalogFixture::new();
    let admitted = {
        let slot = ProviderSlot::new(&fixture);
        slot.admit_decoded(&fixture, fixture.context.clone(), Currentness::Available)
            .unwrap()
    };
    assert!(admitted.slot.upgrade().is_none());
    let replacement_slot = ProviderSlot::new(&fixture);
    assert_eq!(
        replacement_slot.verify_use(
            &fixture,
            &admitted,
            Currentness::Available,
            &minimal_evidence(),
            |_| {},
        ),
        Err(Refusal::ProviderDestroyed)
    );
    assert_eq!(replacement_slot.trace().sentinel_effects, 0);

    let slot = ProviderSlot::new(&fixture);
    let admitted = slot
        .admit_decoded(&fixture, fixture.context.clone(), Currentness::Available)
        .unwrap();
    let charged = slot.logical_charge();
    slot.set_next_identities_for_test(u64::MAX, u64::MAX);
    assert_eq!(
        slot.replace_current(&fixture),
        Err(Refusal::IdentityExhausted)
    );
    assert_eq!(slot.logical_charge(), charged);
    assert!(slot.has_lease());
    slot.verify_use(
        &fixture,
        &admitted,
        Currentness::Available,
        &minimal_evidence(),
        |_| {},
    )
    .unwrap();
    drop(admitted);
    assert_eq!(slot.logical_charge(), 0);

    let lease_exhausted_slot = ProviderSlot::new(&fixture);
    lease_exhausted_slot.set_next_identities_for_test(2, u64::MAX);
    let next = lease_exhausted_slot
        .admit_decoded(&fixture, fixture.context.clone(), Currentness::Available)
        .err()
        .unwrap();
    assert_eq!(next, Refusal::LeaseExhausted);
    assert!(lease_exhausted_slot.replace_current(&fixture).is_ok());
}

#[test]
fn descriptor_gate_materialization_and_descriptor_correspondence() {
    let fixture = ExpectedCatalogFixture::new();
    let candidate = encode_candidate(&fixture.context);
    let evidence = encode_evidence(&[vec![1]]);
    assert_eq!(candidate.len(), 11_339);
    assert_eq!(evidence.len(), 16);

    let slot = ProviderSlot::new(&fixture);
    let mut called = false;
    assert_eq!(
        slot.admit_descriptor(
            &fixture,
            Descriptor {
                candidate_len: MAX_CANDIDATE + 1,
                evidence_len: evidence.len(),
            },
            || {
                called = true;
                (candidate.clone(), evidence.clone())
            },
            Currentness::Available,
        )
        .err(),
        Some(Refusal::CandidateTooLarge)
    );
    assert!(!called);
    assert_eq!(slot.trace().materializers, 0);

    let gate = Rc::new(RefCell::new(Trace::default()));
    assert_eq!(
        descriptor_size_gate(
            Descriptor {
                candidate_len: MAX_CANDIDATE,
                evidence_len: MAX_EVIDENCE,
            },
            &gate,
        ),
        Ok(())
    );
    assert_eq!(MAX_CANDIDATE.checked_add(MAX_EVIDENCE), Some(MAX_COMBINED));
    assert_eq!(
        MAX_COMBINED.checked_add(1),
        Some(MAX_CANDIDATE + MAX_EVIDENCE + 1)
    );
    assert_eq!(MAX_CANDIDATE.checked_add(usize::MAX), None);
    assert_eq!(
        descriptor_size_gate(
            Descriptor {
                candidate_len: MAX_CANDIDATE,
                evidence_len: usize::MAX,
            },
            &gate,
        ),
        Err(Refusal::EvidenceTooLarge)
    );
    assert_eq!(
        checked_combined_len(usize::MAX, 1),
        Err(Refusal::LengthOverflow)
    );
    assert_eq!(gate.borrow().descriptor_size_checks, 2);

    let mut size_gate_only = vec![0; MAX_CANDIDATE];
    size_gate_only[..8].copy_from_slice(CANDIDATE_MAGIC);
    size_gate_only[8..12].copy_from_slice(&(MAX_CANDIDATE as u32).to_le_bytes());
    let size_gate_evidence = minimal_evidence();
    let slot = ProviderSlot::new(&fixture);
    assert_eq!(
        slot.admit_descriptor(
            &fixture,
            Descriptor {
                candidate_len: MAX_CANDIDATE,
                evidence_len: size_gate_evidence.len(),
            },
            || (size_gate_only, size_gate_evidence),
            Currentness::Available,
        )
        .err(),
        Some(Refusal::Unsupported)
    );
    assert_eq!(slot.trace().descriptor_size_checks, 1);
    assert_eq!(slot.trace().materializers, 1);
    assert_eq!(slot.trace().actual_size_checks, 2);
    assert_eq!(slot.trace().borrowed_scans, 1);
    assert_eq!(slot.trace().candidate_decoder_calls, 0);
    assert_eq!(slot.trace().admissions, 0);

    let slot = ProviderSlot::new(&fixture);
    let admitted = slot
        .admit_descriptor(
            &fixture,
            Descriptor {
                candidate_len: candidate.len(),
                evidence_len: evidence.len(),
            },
            || (candidate.clone(), evidence.clone()),
            Currentness::Available,
        )
        .unwrap();
    assert_eq!(slot.trace().materializers, 1);
    assert_eq!(slot.trace().borrowed_scans, 1);
    assert_eq!(slot.trace().decoders, 2);
    drop(admitted);

    let slot = ProviderSlot::new(&fixture);
    assert_eq!(
        slot.admit_descriptor(
            &fixture,
            Descriptor {
                candidate_len: candidate.len(),
                evidence_len: evidence.len(),
            },
            || (candidate[..candidate.len() - 1].to_vec(), evidence.clone()),
            Currentness::Available,
        )
        .err(),
        Some(Refusal::DescriptorMismatch)
    );
    assert_eq!(slot.trace().materializers, 1);
    assert_eq!(slot.trace().borrowed_scans, 0);
    assert_eq!(slot.trace().decoders, 0);

    let slot = ProviderSlot::new(&fixture);
    assert_eq!(
        slot.admit_descriptor(
            &fixture,
            Descriptor {
                candidate_len: candidate.len(),
                evidence_len: evidence.len(),
            },
            || {
                let mut longer = candidate.clone();
                longer.push(0);
                (longer, evidence.clone())
            },
            Currentness::Available,
        )
        .err(),
        Some(Refusal::DescriptorMismatch)
    );
    assert_eq!(slot.trace().borrowed_scans, 0);

    for returned_evidence in [evidence[..evidence.len() - 1].to_vec(), {
        let mut longer = evidence.clone();
        longer.push(0);
        longer
    }] {
        let slot = ProviderSlot::new(&fixture);
        assert_eq!(
            slot.admit_descriptor(
                &fixture,
                Descriptor {
                    candidate_len: candidate.len(),
                    evidence_len: evidence.len(),
                },
                || (candidate.clone(), returned_evidence),
                Currentness::Available,
            )
            .err(),
            Some(Refusal::DescriptorMismatch)
        );
        assert_eq!(slot.trace().actual_size_checks, 1);
        assert_eq!(slot.trace().borrowed_scans, 0);
        assert_eq!(slot.trace().decoders, 0);
    }

    let slot = ProviderSlot::new(&fixture);
    assert_eq!(
        slot.admit_descriptor(
            &fixture,
            Descriptor {
                candidate_len: candidate.len(),
                evidence_len: evidence.len(),
            },
            || {
                let mut oversized = candidate.clone();
                oversized.resize(MAX_CANDIDATE + 1, 0);
                (oversized, evidence.clone())
            },
            Currentness::Available,
        )
        .err(),
        Some(Refusal::CandidateTooLarge)
    );
    assert_eq!(slot.trace().actual_size_checks, 1);
    assert_eq!(slot.trace().borrowed_scans, 0);

    let restored = ProviderSlot::new(&fixture)
        .admit_descriptor(
            &fixture,
            Descriptor {
                candidate_len: candidate.len(),
                evidence_len: evidence.len(),
            },
            || (candidate.clone(), evidence.clone()),
            Currentness::Available,
        )
        .unwrap();
    drop(restored);
}

#[test]
fn borrowed_envelope_max_schema_and_separate_evidence_caps() {
    let fixture = ExpectedCatalogFixture::new();
    let candidate = encode_candidate(&fixture.context);
    let evidence = valid_evidence();
    assert_eq!(candidate.len(), 11_339);
    assert_eq!(evidence.len(), MAX_EVIDENCE);
    assert_eq!(candidate.len() + evidence.len(), 30_728);

    let slot = ProviderSlot::new(&fixture);
    let admitted = slot
        .admit_borrowed(&fixture, &candidate, &evidence, Currentness::Available)
        .unwrap();
    assert_eq!(slot.trace().borrowed_scans, 1);
    assert_eq!(slot.trace().decoders, 2);
    assert_eq!(slot.trace().crypto_calls, 0);
    drop(admitted);

    let mut over_cap = evidence.clone();
    over_cap.push(0);
    let slot = ProviderSlot::new(&fixture);
    assert_eq!(
        slot.admit_borrowed(&fixture, &candidate, &over_cap, Currentness::Available)
            .err(),
        Some(Refusal::EvidenceTooLarge)
    );
    assert_eq!(slot.trace().evidence_count_checks, 0);
    assert_eq!(slot.trace().decoders, 0);
}

#[test]
fn nested_evidence_count_and_length_controls_are_stage_specific() {
    let fixture = ExpectedCatalogFixture::new();
    let candidate = encode_candidate(&fixture.context);

    let count_positive = encode_evidence(&(1..=8).map(|id| vec![id; 1]).collect::<Vec<_>>());
    let count_negative = encode_evidence(&(1..=9).map(|id| vec![id; 1]).collect::<Vec<_>>());
    assert_eq!((count_positive.len(), count_negative.len()), (37, 40));
    for frame in [&count_positive, &count_negative] {
        assert_eq!(
            u32::from_le_bytes(frame[8..12].try_into().unwrap()) as usize,
            frame.len()
        );
        assert_eq!(
            usize::from(frame[12]),
            if frame.len() == 37 { 8 } else { 9 }
        );
    }
    let slot = ProviderSlot::new(&fixture);
    let admitted = slot
        .admit_borrowed(
            &fixture,
            &candidate,
            &count_positive,
            Currentness::Available,
        )
        .unwrap();
    assert_eq!(slot.trace().evidence_outer_size_checks, 1);
    assert_eq!(slot.trace().evidence_frame_checks, 1);
    assert_eq!(slot.trace().evidence_count_checks, 1);
    assert_eq!(slot.trace().evidence_entry_length_checks, 1);
    assert_eq!(slot.trace().evidence_decoder_calls, 1);
    assert_eq!(slot.trace().candidate_decoder_calls, 1);
    assert_eq!(slot.trace().decoders, 2);
    drop(admitted);

    let slot = ProviderSlot::new(&fixture);
    assert_eq!(
        slot.admit_borrowed(
            &fixture,
            &candidate,
            &count_negative,
            Currentness::Available
        )
        .err(),
        Some(Refusal::EvidenceEntryCountExceeded)
    );
    let trace = slot.trace();
    assert_eq!(
        (
            trace.evidence_outer_size_checks,
            trace.evidence_frame_checks,
            trace.evidence_count_checks,
            trace.evidence_entry_length_checks,
            trace.evidence_decoder_calls,
            trace.candidate_decoder_calls,
            trace.decoders,
            trace.crypto_calls
        ),
        (1, 1, 1, 0, 0, 0, 0, 0)
    );
    let restored = slot
        .admit_borrowed(
            &fixture,
            &candidate,
            &count_positive,
            Currentness::Available,
        )
        .unwrap();
    assert_eq!(slot.trace().admissions, 1);
    assert_eq!(slot.trace().decoders, 2);
    drop(restored);

    let length_positive = encode_evidence(&[vec![0xA5; 2_420]]);
    let length_negative = encode_evidence(&[vec![0xA5; 2_421]]);
    assert_eq!(
        (length_positive.len(), length_negative.len()),
        (2_435, 2_436)
    );
    for frame in [&length_positive, &length_negative] {
        assert_eq!(
            u32::from_le_bytes(frame[8..12].try_into().unwrap()) as usize,
            frame.len()
        );
        assert_eq!(
            usize::from(u16::from_le_bytes(frame[13..15].try_into().unwrap())),
            frame.len() - 15
        );
    }
    let slot = ProviderSlot::new(&fixture);
    let admitted = slot
        .admit_borrowed(
            &fixture,
            &candidate,
            &length_positive,
            Currentness::Available,
        )
        .unwrap();
    assert_eq!(slot.trace().evidence_entry_length_checks, 1);
    assert_eq!(slot.trace().evidence_decoder_calls, 1);
    assert_eq!(slot.trace().candidate_decoder_calls, 1);
    assert_eq!(slot.trace().decoders, 2);
    drop(admitted);

    let slot = ProviderSlot::new(&fixture);
    assert_eq!(
        slot.admit_borrowed(
            &fixture,
            &candidate,
            &length_negative,
            Currentness::Available
        )
        .err(),
        Some(Refusal::EvidenceEntryTooLarge)
    );
    let trace = slot.trace();
    assert_eq!(
        (
            trace.evidence_outer_size_checks,
            trace.evidence_frame_checks,
            trace.evidence_count_checks,
            trace.evidence_entry_length_checks,
            trace.evidence_decoder_calls,
            trace.candidate_decoder_calls,
            trace.decoders,
            trace.crypto_calls
        ),
        (1, 1, 1, 1, 0, 0, 0, 0)
    );

    let slot = ProviderSlot::new(&fixture);
    let restored = slot
        .admit_borrowed(
            &fixture,
            &candidate,
            &length_positive,
            Currentness::Available,
        )
        .unwrap();
    assert_eq!(slot.trace().admissions, 1);
    assert_eq!(slot.trace().decoders, 2);
    drop(restored);
}

#[test]
fn nested_evidence_rejects_empty_count_and_entry_lengths() {
    let fixture = ExpectedCatalogFixture::new();
    let candidate = encode_candidate(&fixture.context);
    for (frame, expected, entry_length_checks) in [
        (encode_evidence(&[]), Refusal::EvidenceEntryCountInvalid, 0),
        (
            encode_evidence(&[Vec::new()]),
            Refusal::EvidenceEntryLengthInvalid,
            1,
        ),
    ] {
        let slot = ProviderSlot::new(&fixture);
        assert_eq!(
            slot.admit_borrowed(&fixture, &candidate, &frame, Currentness::Available)
                .err(),
            Some(expected)
        );
        let trace = slot.trace();
        assert_eq!(trace.evidence_outer_size_checks, 1);
        assert_eq!(trace.evidence_frame_checks, 1);
        assert_eq!(trace.evidence_count_checks, 1);
        assert_eq!(trace.evidence_entry_length_checks, entry_length_checks);
        assert_eq!(trace.decoders, 0);
        assert_eq!(trace.crypto_calls, 0);
    }
}

#[test]
fn scanner_rejects_malformed_and_duplicate_candidates_before_decoder() {
    let fixture = ExpectedCatalogFixture::new();
    let evidence = encode_evidence(&[vec![1]]);
    let candidate = encode_candidate(&fixture.context);
    let mut duplicate_id = fixture.context.clone();
    duplicate_id.members[1].identity = duplicate_id.members[0].identity;
    let mut duplicate_key = fixture.context.clone();
    duplicate_key.members[1].public_key = duplicate_key.members[0].public_key.clone();

    for (bad, expected) in [
        (encode_candidate(&duplicate_id), Refusal::AmbiguousIdentity),
        (encode_candidate(&duplicate_key), Refusal::AmbiguousKey),
    ] {
        let slot = ProviderSlot::new(&fixture);
        assert_eq!(
            slot.admit_borrowed(&fixture, &bad, &evidence, Currentness::Available)
                .err(),
            Some(expected)
        );
        assert_eq!(slot.trace().decoders, 1); // evidence scanner only
        assert_eq!(slot.trace().uniqueness_checks, 1);
        assert_eq!(slot.trace().admissions, 0);
    }

    let mut trailing = candidate.clone();
    trailing.push(0);
    let slot = ProviderSlot::new(&fixture);
    assert_eq!(
        slot.admit_borrowed(&fixture, &trailing, &evidence, Currentness::Available)
            .err(),
        Some(Refusal::Malformed)
    );
    assert_eq!(slot.trace().decoders, 1);
}

#[test]
fn candidate_member_source_content_limits_and_restored_positive() {
    let fixture = ExpectedCatalogFixture::new();
    let evidence = encode_evidence(&[vec![1]]);
    let cases: [(fn(&mut Candidate), Refusal, usize, usize); 4] = [
        (
            |candidate| {
                candidate.members.push(Member {
                    identity: [9; 32],
                    public_key: vec![0x59; KEY_BYTES],
                    weight: 1,
                });
            },
            Refusal::MemberLimitExceeded,
            1,
            0,
        ),
        (
            |candidate| candidate.members[0].public_key.push(0x52),
            Refusal::FieldLimitExceeded,
            1,
            1,
        ),
        (
            |candidate| candidate.provenance_source.push(0x41),
            Refusal::FieldLimitExceeded,
            0,
            0,
        ),
        (
            |candidate| candidate.content.push(0x61),
            Refusal::FieldLimitExceeded,
            0,
            0,
        ),
    ];
    for (mutate, expected, member_count_checks, member_length_checks) in cases {
        let mut malformed = fixture.context.clone();
        mutate(&mut malformed);
        let bytes = encode_candidate(&malformed);
        assert!(bytes.len() <= MAX_CANDIDATE);
        let slot = ProviderSlot::new(&fixture);
        assert_eq!(
            slot.admit_borrowed(&fixture, &bytes, &evidence, Currentness::Available)
                .err(),
            Some(expected)
        );
        assert_eq!(slot.trace().decoders, 1);
        assert_eq!(slot.trace().admissions, 0);
        assert_eq!(slot.trace().candidate_frame_checks, 1);
        assert_eq!(slot.trace().candidate_field_checks, 1);
        assert_eq!(
            slot.trace().candidate_member_count_checks,
            member_count_checks
        );
        assert_eq!(
            slot.trace().candidate_member_length_checks,
            member_length_checks
        );

        let valid = encode_candidate(&fixture.context);
        let restored = slot
            .admit_borrowed(&fixture, &valid, &evidence, Currentness::Available)
            .unwrap();
        assert_eq!(slot.trace().admissions, 1);
        drop(restored);
    }
}
