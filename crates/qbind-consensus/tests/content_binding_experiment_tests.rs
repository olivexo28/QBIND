//! Hypothetical complete-statement experiment. No consensus/recovery protocol,
//! production caller, historical attestation or participation authority.

use qbind_crypto::consensus_sig::{ConsensusSigError, ConsensusSigVerifier};
use qbind_crypto::ml_dsa44::MlDsa44Backend;

const TAG: &[u8; 16] = b"QBIND-TEST-CBND1";
const CONTENT_CAP: usize = 256;
const FIXED_BYTES: usize = 16 + 2 + 2 + 8 + 8 + 32 + 32 + 2;
const SIGNATURE_BYTES: usize = 2420;
pub(crate) const QUORUM: usize = 3;
pub(crate) const COMMITTEE: usize = 4;

#[derive(Clone)]
pub(crate) struct Statement {
    pub(crate) version: u16,
    pub(crate) purpose: u16,
    pub(crate) chain: u64,
    pub(crate) epoch: u64,
    pub(crate) authority: [u8; 32],
    pub(crate) parent: [u8; 32],
    pub(crate) content: Vec<u8>,
}

#[derive(Clone, Copy)]
enum Field {
    Version,
    Purpose,
    Chain,
    Epoch,
    Authority,
    Parent,
    Content,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct TestDefect {
    omit_field: Option<Field>,
    omit_uniqueness: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    ContentTooLarge,
    TooManyEndorsements,
    Duplicate(u16),
    Unauthorized(u16),
    SignatureLength(u16),
    InvalidSignature(u16),
    Insufficient { have: usize, need: usize },
}

#[derive(Default)]
pub(crate) struct Trace {
    pub(crate) encoding_calls: usize,
    pub(crate) backend_calls: usize,
    pub(crate) verified_entries: usize,
}

// Defect branches exist only in this integration target. A zeroed field models
// omission without introducing a second parser or ambiguous concatenation.
fn test_encode(
    statement: &Statement,
    defect: TestDefect,
    trace: &mut Trace,
) -> Result<Vec<u8>, Refusal> {
    if statement.content.len() > CONTENT_CAP {
        return Err(Refusal::ContentTooLarge);
    }
    trace.encoding_calls += 1;
    let mut bytes = Vec::with_capacity(FIXED_BYTES + statement.content.len());
    bytes.extend_from_slice(TAG);
    bytes.extend_from_slice(&statement.version.to_le_bytes());
    bytes.extend_from_slice(&statement.purpose.to_le_bytes());
    bytes.extend_from_slice(&statement.chain.to_le_bytes());
    bytes.extend_from_slice(&statement.epoch.to_le_bytes());
    bytes.extend_from_slice(&statement.authority);
    bytes.extend_from_slice(&statement.parent);
    bytes.extend_from_slice(&(statement.content.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&statement.content);
    if let Some(field) = defect.omit_field {
        let range = match field {
            Field::Version => 16..18,
            Field::Purpose => 18..20,
            Field::Chain => 20..28,
            Field::Epoch => 28..36,
            Field::Authority => 36..68,
            Field::Parent => 68..100,
            Field::Content => 102..bytes.len(),
        };
        bytes[range].fill(0);
    }
    Ok(bytes)
}

#[derive(Clone)]
pub(crate) struct Endorsement {
    pub(crate) signer: u16,
    pub(crate) signature: Vec<u8>,
}

pub(crate) struct Fixture {
    pub(crate) statement: Statement,
    pub(crate) public: [Vec<u8>; COMMITTEE],
    pub(crate) endorsements: Vec<Endorsement>,
}

impl Fixture {
    pub(crate) fn new(defect: TestDefect) -> Self {
        let statement = Statement {
            version: 1,
            purpose: 7,
            chain: 5,
            epoch: 9,
            authority: [0xA5; 32],
            parent: [0x3C; 32],
            content: vec![0x7E; CONTENT_CAP],
        };
        let encoded = test_encode(&statement, defect, &mut Trace::default()).unwrap();
        let mut endorsements = Vec::new();
        let public = std::array::from_fn(|id| {
            let (pk, mut sk) = MlDsa44Backend::generate_keypair().expect("synthetic keygen");
            if id < QUORUM {
                endorsements.push(Endorsement {
                    signer: id as u16,
                    signature: MlDsa44Backend::sign(&sk, &encoded)
                        .expect("synthetic hypothetical-statement signature"),
                });
            }
            sk.fill(0);
            pk
        });
        Self {
            statement,
            public,
            endorsements,
        }
    }

    fn verify(
        &self,
        statement: &Statement,
        endorsements: &[Endorsement],
        defect: TestDefect,
    ) -> (Result<usize, Refusal>, Trace) {
        let mut trace = Trace::default();
        let result = test_verify(statement, endorsements, &self.public, defect, &mut trace);
        (result, trace)
    }
}

pub(crate) fn test_verify(
    statement: &Statement,
    endorsements: &[Endorsement],
    public: &[Vec<u8>; COMMITTEE],
    defect: TestDefect,
    trace: &mut Trace,
) -> Result<usize, Refusal> {
    if endorsements.len() > COMMITTEE {
        return Err(Refusal::TooManyEndorsements);
    }
    let mut seen = [false; COMMITTEE];
    for entry in endorsements {
        let index = usize::from(entry.signer);
        if index >= COMMITTEE {
            return Err(Refusal::Unauthorized(entry.signer));
        }
        if !defect.omit_uniqueness && seen[index] {
            return Err(Refusal::Duplicate(entry.signer));
        }
        seen[index] = true;
        if entry.signature.len() != SIGNATURE_BYTES {
            return Err(Refusal::SignatureLength(entry.signer));
        }
    }
    let encoded = test_encode(statement, defect, trace)?;
    for entry in endorsements {
        trace.backend_calls += 1;
        // Raw real backend reuse only, not the message-bound Vote/QC verifier.
        match MlDsa44Backend.verify_vote(
            u64::from(entry.signer),
            &public[usize::from(entry.signer)],
            &encoded,
            &entry.signature,
        ) {
            Ok(()) => trace.verified_entries += 1,
            Err(ConsensusSigError::InvalidSignature) => {
                return Err(Refusal::InvalidSignature(entry.signer));
            }
            Err(error) => panic!("unexpected real-backend failure: {error}"),
        }
    }
    if trace.verified_entries < QUORUM {
        return Err(Refusal::Insufficient {
            have: trace.verified_entries,
            need: QUORUM,
        });
    }
    Ok(trace.verified_entries)
}

fn changed(original: &Statement, field: Field) -> Statement {
    let mut result = original.clone();
    match field {
        Field::Version => result.version += 1,
        Field::Purpose => result.purpose += 1,
        Field::Chain => result.chain += 1,
        Field::Epoch => result.epoch += 1,
        Field::Authority => result.authority[31] ^= 1,
        Field::Parent => result.parent[31] ^= 1,
        Field::Content => result.content[255] ^= 1,
    }
    result
}

fn fields() -> [Field; 7] {
    [
        Field::Version,
        Field::Purpose,
        Field::Chain,
        Field::Epoch,
        Field::Authority,
        Field::Parent,
        Field::Content,
    ]
}

#[test]
fn exact_complete_encoding_and_separate_fixture_accounting() {
    let f = Fixture::new(TestDefect::default());
    let bytes = test_encode(&f.statement, TestDefect::default(), &mut Trace::default()).unwrap();
    let mut expected = b"QBIND-TEST-CBND1".to_vec();
    expected.extend_from_slice(&[1, 0, 7, 0, 5, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0]);
    expected.extend_from_slice(&[0xA5; 32]);
    expected.extend_from_slice(&[0x3C; 32]);
    expected.extend_from_slice(&[0, 1]);
    expected.extend_from_slice(&[0x7E; 256]);
    assert_eq!(bytes, expected);
    assert_eq!(bytes.len(), 358);
    let signature_lengths = f
        .endorsements
        .iter()
        .map(|entry| entry.signature.len())
        .sum::<usize>();
    assert_eq!(signature_lengths, 7260);
    // Test-only bundle accounting: u16 count, each u16 id/u16 sig length.
    let bundle = bytes.len() + 2 + QUORUM * 4 + signature_lengths;
    assert_eq!(bundle, 7632);
    assert_eq!(
        FIXED_BYTES + CONTENT_CAP + 2 + COMMITTEE * (4 + SIGNATURE_BYTES),
        10056
    );
    assert_eq!(f.public.iter().map(Vec::len).sum::<usize>(), 5248);
    println!("ACCOUNTING statement=358 bundle=7632 maximum_bundle=10056 signatures=7260 public_keys=5248 sequential_setup_secret_key=2560; decoded+encoded coexist; total memory/work/runtime UNMEASURED");
}

#[test]
fn sufficient_unique_synthetic_signatures_pass_and_restore() {
    let f = Fixture::new(TestDefect::default());
    for _ in 0..2 {
        let (result, trace) = f.verify(&f.statement, &f.endorsements, TestDefect::default());
        assert_eq!(result, Ok(3));
        assert_eq!(
            (
                trace.encoding_calls,
                trace.backend_calls,
                trace.verified_entries
            ),
            (1, 3, 3)
        );
    }
}

#[test]
fn every_complete_field_mutation_refuses_original_signatures_and_restores() {
    let f = Fixture::new(TestDefect::default());
    for field in fields() {
        let (result, trace) = f.verify(
            &changed(&f.statement, field),
            &f.endorsements,
            TestDefect::default(),
        );
        assert_eq!(result, Err(Refusal::InvalidSignature(0)));
        assert_eq!(
            (
                trace.encoding_calls,
                trace.backend_calls,
                trace.verified_entries
            ),
            (1, 1, 0)
        );
        let (restored, trace) = f.verify(&f.statement, &f.endorsements, TestDefect::default());
        assert_eq!(restored, Ok(3));
        assert_eq!(trace.backend_calls, 3);
    }
    println!("BINDING seven same-path field mutations refused; full parent/content suffix included; each restored original passed");
}

#[test]
fn duplicate_unauthorized_and_insufficient_entries_never_add_weight() {
    let f = Fixture::new(TestDefect::default());
    let duplicate = vec![f.endorsements[0].clone(); 3];
    let (result, trace) = f.verify(&f.statement, &duplicate, TestDefect::default());
    assert_eq!(result, Err(Refusal::Duplicate(0)));
    assert_eq!(
        (
            trace.encoding_calls,
            trace.backend_calls,
            trace.verified_entries
        ),
        (0, 0, 0)
    );
    let mut unauthorized = f.endorsements.clone();
    unauthorized[2].signer = 4;
    let (result, trace) = f.verify(&f.statement, &unauthorized, TestDefect::default());
    assert_eq!(result, Err(Refusal::Unauthorized(4)));
    assert_eq!(
        (
            trace.encoding_calls,
            trace.backend_calls,
            trace.verified_entries
        ),
        (0, 0, 0)
    );
    let (result, trace) = f.verify(&f.statement, &f.endorsements[..2], TestDefect::default());
    assert_eq!(result, Err(Refusal::Insufficient { have: 2, need: 3 }));
    assert_eq!((trace.backend_calls, trace.verified_entries), (2, 2));
    assert_eq!(
        f.verify(&f.statement, &f.endorsements, TestDefect::default())
            .0,
        Ok(3)
    );
}

#[test]
fn omitted_field_defects_accept_substitutions_and_are_detected() {
    for field in fields() {
        let defect = TestDefect {
            omit_field: Some(field),
            omit_uniqueness: false,
        };
        // New synthetic signatures over deliberately defective bytes. Never
        // reinterpret signatures made over the complete statement.
        let f = Fixture::new(defect);
        assert_eq!(f.verify(&f.statement, &f.endorsements, defect).0, Ok(3));
        let (defective, trace) = f.verify(&changed(&f.statement, field), &f.endorsements, defect);
        assert_eq!(defective, Ok(3));
        assert_ne!(defective, Err(Refusal::InvalidSignature(0)));
        assert_eq!(trace.backend_calls, 3);
        assert_eq!(
            f.verify(&f.statement, &f.endorsements, TestDefect::default())
                .0,
            Err(Refusal::InvalidSignature(0))
        );
        let complete = Fixture::new(TestDefect::default());
        assert_eq!(
            complete
                .verify(
                    &changed(&complete.statement, field),
                    &complete.endorsements,
                    TestDefect::default()
                )
                .0,
            Err(Refusal::InvalidSignature(0))
        );
        assert_eq!(
            complete
                .verify(
                    &complete.statement,
                    &complete.endorsements,
                    TestDefect::default()
                )
                .0,
            Ok(3)
        );
    }
    println!("SENSITIVITY omitted-field test-only encoding accepts substitutions for all seven fields; intended refusal assertion would fail; complete path refuses/restores");
}

#[test]
fn omitted_uniqueness_defect_counts_one_signer_three_times_and_is_detected() {
    let f = Fixture::new(TestDefect::default());
    let duplicate = vec![f.endorsements[0].clone(); 3];
    assert_eq!(
        f.verify(&f.statement, &duplicate, TestDefect::default()).0,
        Err(Refusal::Duplicate(0))
    );
    let defect = TestDefect {
        omit_field: None,
        omit_uniqueness: true,
    };
    let (defective, trace) = f.verify(&f.statement, &duplicate, defect);
    assert_eq!(defective, Ok(3));
    assert_eq!((trace.backend_calls, trace.verified_entries), (3, 3));
    assert_ne!(defective, Err(Refusal::Duplicate(0)));
    assert_eq!(
        f.verify(&f.statement, &duplicate[..1], TestDefect::default())
            .0,
        Err(Refusal::Insufficient { have: 1, need: 3 })
    );
    assert_eq!(
        f.verify(&f.statement, &f.endorsements, TestDefect::default())
            .0,
        Ok(3)
    );
    println!("SENSITIVITY uniqueness bypass test-only: one real signature reused three times; fixture quorum incorrectly passes; strict path refuses and distinct originals restore");
}

#[test]
fn allocated_oversized_or_malformed_inputs_refuse_before_encoding_and_crypto() {
    let f = Fixture::new(TestDefect::default());
    let mut oversized = f.statement.clone();
    oversized.content.push(0);
    let (result, trace) = f.verify(&oversized, &f.endorsements, TestDefect::default());
    assert_eq!(result, Err(Refusal::ContentTooLarge));
    assert_eq!((trace.encoding_calls, trace.backend_calls), (0, 0));
    let mut excess = f.endorsements.clone();
    excess.extend_from_slice(&f.endorsements[..2]);
    assert_eq!(
        f.verify(&f.statement, &excess, TestDefect::default()).0,
        Err(Refusal::TooManyEndorsements)
    );
    let mut malformed = f.endorsements.clone();
    malformed[2].signature.pop();
    let (result, trace) = f.verify(&f.statement, &malformed, TestDefect::default());
    assert_eq!(result, Err(Refusal::SignatureLength(2)));
    assert_eq!((trace.encoding_calls, trace.backend_calls), (0, 0));
    let mut corrupted = f.endorsements.clone();
    corrupted[2].signature[0] ^= 1;
    let (result, trace) = f.verify(&f.statement, &corrupted, TestDefect::default());
    assert_eq!(result, Err(Refusal::InvalidSignature(2)));
    assert_eq!((trace.backend_calls, trace.verified_entries), (3, 2));
    assert_eq!(
        f.verify(&f.statement, &f.endorsements, TestDefect::default())
            .0,
        Ok(3)
    );
    println!("LIMITS deliberately allocated negatives: pre-encoding/pre-crypto only, not pre-input-allocation; corrupt last signature refuses without quorum output");
}
