//! Bounded capability model for atomic block publication with retained completion.
//!
//! These are synthetic controls, not QBIND production APIs or a durability test.

use rocksdb::{DB, Options, WriteBatch};
use std::path::Path;

const ACCOUNT_VALUE: &[u8] = b"account:value:synthetic";
const ACCOUNT_MEMBERSHIP: &[u8] = b"account:membership:synthetic";
const EXECUTION_POSITION: &[u8] = b"execution:position:synthetic";
const OPERATION_ID: &[u8] = b"execution:operation-id:synthetic";
const COMPLETION: &[u8] = b"execution:completion:synthetic";
const ALL_KEYS: [&[u8]; 5] = [
    ACCOUNT_VALUE,
    ACCOUNT_MEMBERSHIP,
    EXECUTION_POSITION,
    OPERATION_ID,
    COMPLETION,
];

fn test_db(path: &Path) -> DB {
    let mut options = Options::default();
    options.create_if_missing(true);
    DB::open(&options, path).expect("open test database")
}

fn candidate_batch() -> WriteBatch {
    let mut batch = WriteBatch::default();
    batch.put(ACCOUNT_VALUE, b"balance=42");
    batch.put(ACCOUNT_MEMBERSHIP, b"present");
    batch.put(EXECUTION_POSITION, b"height=7;parent=6");
    batch.put(OPERATION_ID, b"operation-7");
    batch.put(COMPLETION, b"durable-ack:operation-7");
    batch
}

fn assert_all_keys(db: &DB, expected_present: bool) {
    for key in ALL_KEYS {
        assert_eq!(
            db.get(key).expect("read test key").is_some(),
            expected_present,
            "unexpected presence for {}",
            String::from_utf8_lossy(key)
        );
    }
}

#[test]
fn one_database_batch_retains_candidate_and_minimal_completion_after_reopen() {
    let temp = tempfile::tempdir().expect("temporary directory");
    {
        let db = test_db(&temp.path().join("one-db"));
        db.write(candidate_batch()).expect("write one-db batch");
    }

    let db = test_db(&temp.path().join("one-db"));
    assert_all_keys(&db, true);
    assert_eq!(
        db.get(COMPLETION).expect("read completion").unwrap(),
        b"durable-ack:operation-7"
    );
}

#[test]
fn injected_failure_before_one_database_batch_publication_leaves_no_candidate_keys() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let path = temp.path().join("one-db");
    let db = test_db(&path);
    let batch = candidate_batch();

    let injected_failure = true;
    let outcome = if injected_failure {
        Err("injected before DB::write")
    } else {
        db.write(batch).map_err(|_| "DB::write failed")
    };
    assert_eq!(outcome, Err("injected before DB::write"));
    drop(db);

    let db = test_db(&path);
    assert_all_keys(&db, false);
}

#[test]
fn separate_database_calls_can_leave_partial_state_at_injected_boundary() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let account_path = temp.path().join("account-db");
    let metadata_path = temp.path().join("metadata-db");
    {
        let account_db = test_db(&account_path);
        let metadata_db = test_db(&metadata_path);
        account_db
            .put(ACCOUNT_VALUE, b"published account value")
            .expect("write account database");

        let injected_failure_before_metadata_write = true;
        if !injected_failure_before_metadata_write {
            metadata_db
                .write(candidate_batch())
                .expect("write metadata database");
        }
    }

    let account_db = test_db(&account_path);
    let metadata_db = test_db(&metadata_path);
    assert!(account_db
        .get(ACCOUNT_VALUE)
        .expect("read account database")
        .is_some());
    assert_all_keys(&metadata_db, false);
}

#[test]
fn a_lost_response_after_write_is_unknown_even_when_reopen_finds_commit() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let path = temp.path().join("one-db");
    {
        let db = test_db(&path);
        db.write(candidate_batch()).expect("write candidate batch");
        let caller_observed_response = false;
        let caller_outcome = if caller_observed_response {
            "success"
        } else {
            "unknown"
        };
        assert_eq!(caller_outcome, "unknown");
    }

    let db = test_db(&path);
    assert_all_keys(&db, true);
    assert_eq!(
        db.get(COMPLETION).expect("read completion").unwrap(),
        b"durable-ack:operation-7"
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SyntheticProof {
    subject: u8,
    representation: u8,
    valid: bool,
    authorized: bool,
    current: bool,
    equivalence_group: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SyntheticEvidence {
    Proof(SyntheticProof),
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SyntheticRefusal {
    Invalid,
    Unauthorized,
    WrongSubject,
    NonEquivalent,
    Stale,
    Unavailable,
}

fn synthetic_verify(
    expected_subject: u8,
    expected_equivalence_group: u8,
    evidence: SyntheticEvidence,
) -> Result<(), SyntheticRefusal> {
    match evidence {
        SyntheticEvidence::Proof(proof) => {
            assert_ne!(proof.representation, 0, "proof representation must be nonempty");
            if !proof.valid {
                return Err(SyntheticRefusal::Invalid);
            }
            if !proof.authorized {
                return Err(SyntheticRefusal::Unauthorized);
            }
            if proof.subject != expected_subject {
                return Err(SyntheticRefusal::WrongSubject);
            }
            if proof.equivalence_group != expected_equivalence_group {
                return Err(SyntheticRefusal::NonEquivalent);
            }
            if !proof.current {
                return Err(SyntheticRefusal::Stale);
            }
            Ok(())
        }
        SyntheticEvidence::Unavailable => Err(SyntheticRefusal::Unavailable),
    }
}

#[test]
fn synthetic_equivalent_evidence_retrieves_same_completion_and_other_cases_refuse() {
    let operation_subject = 7;
    let equivalent_proof = SyntheticProof {
        subject: operation_subject,
        representation: 1,
        valid: true,
        authorized: true,
        current: true,
        equivalence_group: 3,
    };
    let first_representation = SyntheticEvidence::Proof(equivalent_proof);
    let alternative_representation = SyntheticEvidence::Proof(SyntheticProof {
        representation: 2,
        ..equivalent_proof
    });
    assert_ne!(first_representation, alternative_representation);
    assert_eq!(
        synthetic_verify(operation_subject, 3, first_representation),
        Ok(())
    );
    assert_eq!(
        synthetic_verify(operation_subject, 3, alternative_representation),
        Ok(())
    );

    let retained_completion = b"durable-ack:operation-7";
    let retained = [(operation_subject, retained_completion.as_slice())];
    let lookup = |evidence| {
        synthetic_verify(operation_subject, 3, evidence)
            .map(|()| {
                retained
                    .iter()
                    .find(|(subject, _)| *subject == operation_subject)
                    .map(|(_, completion)| *completion)
                    .expect("retained completion")
            })
    };
    assert_eq!(lookup(alternative_representation), Ok(retained_completion.as_slice()));

    for (evidence, refusal) in [
        (
            SyntheticEvidence::Proof(SyntheticProof {
                valid: false,
                ..equivalent_proof
            }),
            SyntheticRefusal::Invalid,
        ),
        (
            SyntheticEvidence::Proof(SyntheticProof {
                authorized: false,
                ..equivalent_proof
            }),
            SyntheticRefusal::Unauthorized,
        ),
        (
            SyntheticEvidence::Proof(SyntheticProof {
                subject: operation_subject + 1,
                ..equivalent_proof
            }),
            SyntheticRefusal::WrongSubject,
        ),
        (
            SyntheticEvidence::Proof(SyntheticProof {
                equivalence_group: 4,
                ..equivalent_proof
            }),
            SyntheticRefusal::NonEquivalent,
        ),
        (
            SyntheticEvidence::Proof(SyntheticProof {
                current: false,
                ..equivalent_proof
            }),
            SyntheticRefusal::Stale,
        ),
        (
            SyntheticEvidence::Unavailable,
            SyntheticRefusal::Unavailable,
        ),
    ] {
        assert_eq!(lookup(evidence), Err(refusal));
    }
}
