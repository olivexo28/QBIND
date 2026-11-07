//! Independently supplied test context, not external authority or a protocol.

use qbind_crypto::consensus_sig::{ConsensusSigError, ConsensusSigVerifier};
use qbind_crypto::ml_dsa44::MlDsa44Backend;

const MEMBERS: usize = 4;
const CONTENT_CAP: usize = 256;
const PK_BYTES: usize = 1312;
const SIG_BYTES: usize = 2420;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Member {
    id: u16,
    public: Vec<u8>,
    weight: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Context {
    chain: u64,
    epoch: u64,
    authority: [u8; 32],
    threshold: u64,
    members: Vec<Member>,
}

#[derive(Clone)]
struct Statement {
    chain: u64,
    epoch: u64,
    authority: [u8; 32],
    parent: [u8; 32],
    content: Vec<u8>,
}

#[derive(Clone)]
struct Endorsement {
    id: u16,
    signature: Vec<u8>,
}

#[derive(Clone)]
struct Witness {
    statement: Statement,
    claims: Context,
    endorsements: Vec<Endorsement>,
}

#[derive(Clone, Copy, Default)]
enum TestDefect {
    #[default]
    None,
    TrustWitness,
    LabelOnly,
}

#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    MemberCount,
    DuplicateIdentity(u16),
    DuplicateKey,
    KeyLength,
    InvalidWeightOrThreshold,
    ContextMismatch(&'static str),
    StatementMismatch,
    ContentTooLarge,
    EndorsementCount,
    DuplicateSigner(u16),
    Unauthorized(u16),
    SignatureLength(u16),
    InvalidSignature(u16),
    Insufficient { have: u64, need: u64 },
}

#[derive(Default)]
struct Trace {
    context_matches: usize,
    encoding_calls: usize,
    backend_calls: usize,
    valid_weight: u64,
}

fn validate_context(context: &Context) -> Result<(), Refusal> {
    if context.members.len() != MEMBERS {
        return Err(Refusal::MemberCount);
    }
    let mut total = 0u64;
    for (index, member) in context.members.iter().enumerate() {
        if member.public.len() != PK_BYTES {
            return Err(Refusal::KeyLength);
        }
        for previous in &context.members[..index] {
            if previous.id == member.id {
                return Err(Refusal::DuplicateIdentity(member.id));
            }
            if previous.public == member.public {
                return Err(Refusal::DuplicateKey);
            }
        }
        if member.weight == 0 {
            return Err(Refusal::InvalidWeightOrThreshold);
        }
        total = total
            .checked_add(member.weight)
            .ok_or(Refusal::InvalidWeightOrThreshold)?;
    }
    if context.threshold == 0 || context.threshold > total {
        return Err(Refusal::InvalidWeightOrThreshold);
    }
    Ok(())
}

fn compare_context(expected: &Context, claimed: &Context) -> Result<(), Refusal> {
    for (matches, field) in [
        (expected.chain == claimed.chain, "chain"),
        (expected.epoch == claimed.epoch, "epoch"),
        (expected.authority == claimed.authority, "authority"),
        (expected.threshold == claimed.threshold, "threshold"),
        (
            expected.members == claimed.members,
            "members/keys/weights/order",
        ),
    ] {
        if !matches {
            return Err(Refusal::ContextMismatch(field));
        }
    }
    Ok(())
}

fn encode(statement: &Statement, trace: &mut Trace) -> Result<Vec<u8>, Refusal> {
    if statement.content.len() > CONTENT_CAP {
        return Err(Refusal::ContentTooLarge);
    }
    trace.encoding_calls += 1;
    let mut bytes = Vec::with_capacity(102 + statement.content.len());
    bytes.extend_from_slice(b"QBIND-TEST-CBND1");
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&7u16.to_le_bytes());
    bytes.extend_from_slice(&statement.chain.to_le_bytes());
    bytes.extend_from_slice(&statement.epoch.to_le_bytes());
    bytes.extend_from_slice(&statement.authority);
    bytes.extend_from_slice(&statement.parent);
    bytes.extend_from_slice(&(statement.content.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&statement.content);
    Ok(bytes)
}

fn test_verify(
    expected: &Context,
    witness: &Witness,
    defect: TestDefect,
) -> (Result<u64, Refusal>, Trace) {
    let mut trace = Trace::default();
    let result = (|| {
        validate_context(expected)?;
        validate_context(&witness.claims)?;
        let selected = match defect {
            TestDefect::None => {
                compare_context(expected, &witness.claims)?;
                trace.context_matches += 1;
                expected
            }
            TestDefect::TrustWitness => &witness.claims,
            TestDefect::LabelOnly => {
                if expected.authority != witness.claims.authority {
                    return Err(Refusal::ContextMismatch("authority"));
                }
                &witness.claims
            }
        };
        if witness.statement.chain != selected.chain
            || witness.statement.epoch != selected.epoch
            || witness.statement.authority != selected.authority
        {
            return Err(Refusal::StatementMismatch);
        }
        if witness.endorsements.len() > MEMBERS {
            return Err(Refusal::EndorsementCount);
        }
        for (index, entry) in witness.endorsements.iter().enumerate() {
            if witness.endorsements[..index]
                .iter()
                .any(|old| old.id == entry.id)
            {
                return Err(Refusal::DuplicateSigner(entry.id));
            }
            if !selected.members.iter().any(|member| member.id == entry.id) {
                return Err(Refusal::Unauthorized(entry.id));
            }
            if entry.signature.len() != SIG_BYTES {
                return Err(Refusal::SignatureLength(entry.id));
            }
        }
        let bytes = encode(&witness.statement, &mut trace)?;
        for entry in &witness.endorsements {
            let member = selected
                .members
                .iter()
                .find(|member| member.id == entry.id)
                .unwrap();
            trace.backend_calls += 1;
            match MlDsa44Backend.verify_vote(
                u64::from(entry.id),
                &member.public,
                &bytes,
                &entry.signature,
            ) {
                Ok(()) => {
                    trace.valid_weight = trace
                        .valid_weight
                        .checked_add(member.weight)
                        .ok_or(Refusal::InvalidWeightOrThreshold)?;
                }
                Err(ConsensusSigError::InvalidSignature) => {
                    return Err(Refusal::InvalidSignature(entry.id))
                }
                Err(error) => panic!("unexpected real-backend failure: {error}"),
            }
        }
        if trace.valid_weight < selected.threshold {
            return Err(Refusal::Insufficient {
                have: trace.valid_weight,
                need: selected.threshold,
            });
        }
        Ok(trace.valid_weight)
    })();
    (result, trace)
}

// Constructed independently before witness claims are cloned. The verifier
// only borrows this immutable value; it cannot write or replace its context.
fn independently_supplied_fixture() -> (Context, Witness) {
    let statement = Statement {
        chain: 5,
        epoch: 9,
        authority: [0xA5; 32],
        parent: [0x3C; 32],
        content: vec![0x7E; CONTENT_CAP],
    };
    let bytes = encode(&statement, &mut Trace::default()).unwrap();
    let mut members = Vec::new();
    let mut endorsements = Vec::new();
    for id in 0..4u16 {
        let (public, mut secret) = MlDsa44Backend::generate_keypair().expect("synthetic keygen");
        if id < 3 {
            endorsements.push(Endorsement {
                id,
                signature: MlDsa44Backend::sign(&secret, &bytes).expect("synthetic signature"),
            });
        }
        secret.fill(0);
        members.push(Member {
            id,
            public,
            weight: if id == 0 { 2 } else { 1 },
        });
    }
    let expected = Context {
        chain: 5,
        epoch: 9,
        authority: [0xA5; 32],
        threshold: 4,
        members,
    };
    validate_context(&expected).unwrap();
    let witness = Witness {
        statement,
        claims: expected.clone(),
        endorsements,
    };
    (expected, witness)
}

fn restored(expected: &Context, witness: &Witness) {
    let (result, trace) = test_verify(expected, witness, TestDefect::None);
    assert_eq!(result, Ok(4));
    assert_eq!(
        (
            trace.context_matches,
            trace.encoding_calls,
            trace.backend_calls,
            trace.valid_weight
        ),
        (1, 1, 3, 4)
    );
}

#[test]
fn immutable_expected_context_positive_and_separate_accounting() {
    let (expected, witness) = independently_supplied_fixture();
    let before = expected.clone();
    restored(&expected, &witness);
    restored(&expected, &witness);
    assert_eq!(expected, before);
    let statement = encode(&witness.statement, &mut Trace::default()).unwrap();
    assert_eq!(statement.len(), 358);
    assert_eq!(
        expected
            .members
            .iter()
            .map(|member| member.public.len())
            .sum::<usize>(),
        5248
    );
    assert_eq!(
        witness
            .endorsements
            .iter()
            .map(|entry| entry.signature.len())
            .sum::<usize>(),
        7260
    );
    // Conceptual context bytes: chain/epoch/label/threshold/count + members.
    assert_eq!(8 + 8 + 32 + 8 + 2 + MEMBERS * (2 + 8 + 2 + PK_BYTES), 5354);
    assert_eq!(358 + 5354 + 2 + 3 * (2 + 2 + SIG_BYTES), 12986);
    assert_eq!(358 + 5354 + 2 + 4 * (2 + 2 + SIG_BYTES), 15410);
    println!("ACCOUNTING statement=358 conceptual_claim_context=5354 positive_bundle=12986 maximum_bundle=15410 expected_public_keys=5248 claimed_public_keys=5248 signatures=7260 sequential_secret=2560; actual structures allocated, no context serializer; total memory/work UNMEASURED");
}

#[test]
fn same_label_substituted_member_or_public_key_refuses_before_crypto() {
    let (expected, witness) = independently_supplied_fixture();
    let (other, _) = independently_supplied_fixture();
    for kind in 0..2 {
        let mut changed = witness.clone();
        if kind == 0 {
            changed.claims.members[2].id = 7;
        } else {
            changed.claims.members[2].public = other.members[2].public.clone();
        }
        let (result, trace) = test_verify(&expected, &changed, TestDefect::None);
        assert_eq!(
            result,
            Err(Refusal::ContextMismatch("members/keys/weights/order"))
        );
        assert_eq!(
            (
                trace.context_matches,
                trace.encoding_calls,
                trace.backend_calls
            ),
            (0, 0, 0)
        );
        restored(&expected, &witness);
    }
}

#[test]
fn lowered_threshold_and_altered_weight_claims_do_not_override_expected() {
    let (expected, witness) = independently_supplied_fixture();
    for kind in 0..2 {
        let mut changed = witness.clone();
        if kind == 0 {
            changed.claims.threshold = 2;
        } else {
            changed.claims.members[1].weight = 3;
        }
        let (result, trace) = test_verify(&expected, &changed, TestDefect::None);
        assert_eq!(
            result,
            Err(Refusal::ContextMismatch(if kind == 0 {
                "threshold"
            } else {
                "members/keys/weights/order"
            }))
        );
        assert_eq!(trace.backend_calls, 0);
        restored(&expected, &witness);
    }
}

#[test]
fn duplicate_identity_and_key_assignments_refuse_in_expected_and_claims() {
    let (expected, witness) = independently_supplied_fixture();
    for kind in 0..2 {
        let mut malformed = expected.clone();
        if kind == 0 {
            malformed.members[2].id = 0;
        } else {
            malformed.members[2].public = malformed.members[0].public.clone();
        }
        let mut changed = witness.clone();
        changed.claims = malformed.clone();
        for (context, candidate) in [(&expected, &changed), (&malformed, &witness)] {
            let (result, trace) = test_verify(context, candidate, TestDefect::None);
            assert_eq!(
                result,
                Err(if kind == 0 {
                    Refusal::DuplicateIdentity(0)
                } else {
                    Refusal::DuplicateKey
                })
            );
            assert_eq!((trace.encoding_calls, trace.backend_calls), (0, 0));
        }
        restored(&expected, &witness);
    }
}

#[test]
fn duplicate_unauthorized_insufficient_and_corrupt_signatures_refuse() {
    let (expected, witness) = independently_supplied_fixture();
    let mut duplicate = witness.clone();
    duplicate.endorsements = vec![witness.endorsements[0].clone(); 3];
    assert_eq!(
        test_verify(&expected, &duplicate, TestDefect::None).0,
        Err(Refusal::DuplicateSigner(0))
    );
    let mut unauthorized = witness.clone();
    unauthorized.endorsements[2].id = 7;
    let (result, trace) = test_verify(&expected, &unauthorized, TestDefect::None);
    assert_eq!(result, Err(Refusal::Unauthorized(7)));
    assert_eq!(trace.backend_calls, 0);
    let mut insufficient = witness.clone();
    insufficient.endorsements.pop();
    let (result, trace) = test_verify(&expected, &insufficient, TestDefect::None);
    assert_eq!(result, Err(Refusal::Insufficient { have: 3, need: 4 }));
    assert_eq!((trace.backend_calls, trace.valid_weight), (2, 3));
    let mut corrupt = witness.clone();
    corrupt.endorsements[2].signature[0] ^= 1;
    let (result, trace) = test_verify(&expected, &corrupt, TestDefect::None);
    assert_eq!(result, Err(Refusal::InvalidSignature(2)));
    assert_eq!((trace.backend_calls, trace.valid_weight), (3, 3));
    restored(&expected, &witness);
}

#[test]
fn wrong_chain_epoch_authority_statement_and_other_set_context_refuse() {
    let (expected, witness) = independently_supplied_fixture();
    let (other, _) = independently_supplied_fixture();
    for (field, error) in [(0, "chain"), (1, "epoch"), (2, "authority")] {
        let mut changed = witness.clone();
        match field {
            0 => changed.claims.chain += 1,
            1 => changed.claims.epoch += 1,
            _ => changed.claims.authority[31] ^= 1,
        }
        assert_eq!(
            test_verify(&expected, &changed, TestDefect::None).0,
            Err(Refusal::ContextMismatch(error))
        );
        restored(&expected, &witness);
    }
    for field in 0..2 {
        let mut changed = witness.clone();
        if field == 0 {
            changed.statement.chain += 1;
        } else {
            changed.statement.epoch += 1;
        }
        let (result, trace) = test_verify(&expected, &changed, TestDefect::None);
        assert_eq!(result, Err(Refusal::StatementMismatch));
        assert_eq!((trace.encoding_calls, trace.backend_calls), (0, 0));
        restored(&expected, &witness);
    }
    assert_eq!(
        test_verify(&other, &witness, TestDefect::None).0,
        Err(Refusal::ContextMismatch("members/keys/weights/order"))
    );
    restored(&expected, &witness);
}

#[test]
fn trusting_witness_threshold_and_weights_is_detected_by_strict_controls() {
    let (expected, witness) = independently_supplied_fixture();
    for kind in 0..2 {
        let mut changed = witness.clone();
        changed.endorsements.pop();
        if kind == 0 {
            changed.claims.threshold = 3;
        } else {
            changed.claims.members[1].weight = 2;
        }
        let (strict, trace) = test_verify(&expected, &changed, TestDefect::None);
        assert_eq!(
            strict,
            Err(Refusal::ContextMismatch(if kind == 0 {
                "threshold"
            } else {
                "members/keys/weights/order"
            }))
        );
        assert_eq!(trace.backend_calls, 0);
        let (defective, trace) = test_verify(&expected, &changed, TestDefect::TrustWitness);
        assert_eq!(defective, Ok(if kind == 0 { 3 } else { 4 }));
        assert_ne!(defective, strict);
        assert_eq!((trace.context_matches, trace.backend_calls), (0, 2));
        restored(&expected, &witness);
    }
    println!("SENSITIVITY witness threshold/weight bypass accepts insufficient expected weight; strict context mismatch detects defect");
}

#[test]
fn label_only_or_witness_committee_trust_accepts_other_keys_and_is_detected() {
    let (expected, witness) = independently_supplied_fixture();
    let (_, attacker) = independently_supplied_fixture();
    assert_eq!(expected.authority, attacker.claims.authority);
    let (strict, trace) = test_verify(&expected, &attacker, TestDefect::None);
    assert_eq!(
        strict,
        Err(Refusal::ContextMismatch("members/keys/weights/order"))
    );
    assert_eq!(trace.backend_calls, 0);
    for defect in [TestDefect::LabelOnly, TestDefect::TrustWitness] {
        let (defective, trace) = test_verify(&expected, &attacker, defect);
        assert_eq!(defective, Ok(4));
        assert_ne!(defective, strict);
        assert_eq!(
            (
                trace.context_matches,
                trace.backend_calls,
                trace.valid_weight
            ),
            (0, 3, 4)
        );
    }
    restored(&expected, &witness);
    println!("SENSITIVITY same label/new synthetic committee: defective label-only and witness-trust branches pass; strict expected context refuses; no external authority established");
}

#[test]
fn allocated_fixture_bounds_and_invalid_contexts_refuse_without_crypto() {
    let (expected, witness) = independently_supplied_fixture();
    for kind in 0..6 {
        let mut changed = witness.clone();
        let error = match kind {
            0 => {
                changed.claims.members.pop();
                Refusal::MemberCount
            }
            1 => {
                changed.claims.members[0].public.pop();
                Refusal::KeyLength
            }
            2 => {
                changed.claims.threshold = 0;
                Refusal::InvalidWeightOrThreshold
            }
            3 => {
                changed.claims.members[0].weight = u64::MAX;
                Refusal::InvalidWeightOrThreshold
            }
            4 => {
                changed.statement.content.push(0);
                Refusal::ContentTooLarge
            }
            _ => {
                changed
                    .endorsements
                    .extend_from_slice(&witness.endorsements[..2]);
                Refusal::EndorsementCount
            }
        };
        let (result, trace) = test_verify(&expected, &changed, TestDefect::None);
        assert_eq!(result, Err(error));
        assert_eq!((trace.encoding_calls, trace.backend_calls), (0, 0));
        restored(&expected, &witness);
    }
    let mut changed = witness.clone();
    changed.endorsements[2].signature.pop();
    let (result, trace) = test_verify(&expected, &changed, TestDefect::None);
    assert_eq!(result, Err(Refusal::SignatureLength(2)));
    assert_eq!(trace.backend_calls, 0);
    restored(&expected, &witness);
    println!("LIMITS already allocated vectors: context/count/content/signature/weight checks before encoding or crypto, not pre-input-allocation");
}
