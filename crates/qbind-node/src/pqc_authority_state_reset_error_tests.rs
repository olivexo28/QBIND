//! Private sequencing controls, not a fully verified successful reset fixture.

use super::*;
use crate::pqc_authority_state::load_authority_state;
use crate::pqc_trust_bundle::TrustBundleEnvironment;

fn inputs(dir: &Path) -> AuthorityResetInputs {
    AuthorityResetInputs {
        data_dir: Some(dir.to_path_buf()),
        genesis_path: Some(dir.join("unused-genesis")),
        expected_genesis_hash: Some("invalid".to_string()),
        trust_bundle_path: Some(dir.join("unused-bundle")),
        bundle_signing_key_specs: Vec::new(),
        ratification_path: Some(dir.join("unused-ratification")),
        audit_output_path: Some(dir.join("audit.json")),
        environment: NetworkEnvironment::Devnet,
        operator_note: None,
        validation_time_secs: 0,
        updated_at_unix_secs: 0,
    }
}

fn plan(dir: &Path) -> VerifiedAuthorityResetPlan {
    VerifiedAuthorityResetPlan {
        marker_path: authority_state_file_path(dir),
        environment: NetworkEnvironment::Devnet,
        chain_id_hex_str: "0000000000000001".to_string(),
        genesis_hash_hex_str: "a".repeat(64),
        ratification_hash_hex: "d".repeat(64),
        trust_bundle_fingerprint_hex: "e".repeat(64),
        new_marker: PersistentAuthorityStateRecord::new(
            "0000000000000001".to_string(),
            TrustBundleEnvironment::Devnet,
            "a".repeat(64),
            1,
            5,
            Some(2),
            "b".repeat(40),
            "c".repeat(40),
            "d".repeat(64),
            crate::pqc_authority_state::AuthorityStateUpdateSource::TestOrFixture,
            0,
        ),
        old_marker_archive: OldMarkerArchive {
            present: false,
            raw_sha256_hex: None,
            parsed: None,
        },
        operator_note_hash: None,
    }
}

#[test]
fn verification_and_refusal_audit_failures_remain_inspectable() {
    let dir = tempfile::tempdir().unwrap();
    let inputs = inputs(dir.path());
    let marker = authority_state_file_path(dir.path());
    std::fs::write(&marker, b"synthetic prior bytes").unwrap();
    let mut calls = 0;
    let result = execute_authority_state_reset_with_audit(&inputs, |data, path, record| {
        calls += 1;
        assert_eq!(record.result, "refused");
        write_authority_reset_audit(data, path, record)?;
        Err(AuthorityResetRefusal::AuditWriteFailed(
            "injected after visible audit".into(),
        ))
    })
    .unwrap_err();
    println!("verification double failure: {result:?}");
    match &result {
        AuthorityResetRefusal::AttemptFailed {
            stage,
            marker,
            operation_failure,
            audit_failure,
        } => {
            assert_eq!(*stage, AuthorityResetStage::VerificationRefusalAudit);
            assert_eq!(*marker, MarkerPersistenceOutcome::NotAttempted);
            assert!(matches!(
                operation_failure.as_deref(),
                Some(AuthorityResetRefusal::MalformedExpectedGenesisHash(_))
            ));
            assert!(matches!(
                audit_failure.as_deref(),
                Some(AuthorityResetRefusal::AuditWriteFailed(_))
            ));
        }
        _ => panic!("missing compound failure"),
    }
    assert_eq!(calls, 1);
    assert_eq!(std::fs::read(marker).unwrap(), b"synthetic prior bytes");
    assert!(inputs.audit_output_path.unwrap().exists());
    assert!(result.to_string().contains("NotAttempted"));
}

#[test]
fn persistence_error_and_refusal_audit_error_retain_uncertain_marker() {
    for audit_fails in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let inputs = inputs(dir.path());
        let plan = plan(dir.path());
        let mut publications = Vec::new();
        let mut persistence_calls = 0;
        let result = execute_verified_authority_reset(
            &inputs,
            plan,
            |data, path, record| {
                publications.push(record.result.clone());
                if record.result == "refused" && audit_fails {
                    return Err(AuthorityResetRefusal::AuditWriteFailed(
                        "injected refusal audit".into(),
                    ));
                }
                write_authority_reset_audit(data, path, record)
            },
            |path, record| {
                persistence_calls += 1;
                persist_authority_state_atomic(path, record).unwrap();
                Err(AuthorityResetRefusal::MarkerPersistFailed(
                    "injected after actual persistence".into(),
                ))
            },
        )
        .unwrap_err();
        println!("persistence double failure (audit_fails={audit_fails}): {result:?}");
        match result {
            AuthorityResetRefusal::AttemptFailed {
                stage,
                marker,
                operation_failure,
                audit_failure,
            } => {
                assert_eq!(stage, AuthorityResetStage::MarkerPersistence);
                assert_eq!(marker, MarkerPersistenceOutcome::AttemptedUncertain);
                assert!(matches!(
                    operation_failure.as_deref(),
                    Some(AuthorityResetRefusal::MarkerPersistFailed(_))
                ));
                assert_eq!(audit_failure.is_some(), audit_fails);
                if audit_fails {
                    assert!(matches!(
                        audit_failure.as_deref(),
                        Some(AuthorityResetRefusal::AuditWriteFailed(_))
                    ));
                }
            }
            _ => panic!("missing persistence context"),
        }
        assert_eq!(persistence_calls, 1);
        assert_eq!(publications, ["pending", "refused"]);
        assert!(load_authority_state(&authority_state_file_path(dir.path()))
            .unwrap()
            .is_some());
    }
}

#[test]
fn acknowledged_persistence_survives_success_audit_failure() {
    let dir = tempfile::tempdir().unwrap();
    let inputs = inputs(dir.path());
    let mut publications = Vec::new();
    let mut persistence_calls = 0;
    let result = execute_verified_authority_reset(
        &inputs,
        plan(dir.path()),
        |data, path, record| {
            publications.push(record.result.clone());
            if record.result == "success" {
                return Err(AuthorityResetRefusal::AuditWriteFailed(
                    "injected final audit".into(),
                ));
            }
            write_authority_reset_audit(data, path, record)
        },
        |path, record| {
            persistence_calls += 1;
            persist_authority_state_atomic(path, record)
                .map_err(|e| AuthorityResetRefusal::MarkerPersistFailed(e.to_string()))
        },
    )
    .unwrap_err();
    println!("acknowledged persistence, failed audit: {result:?}");
    match result {
        AuthorityResetRefusal::AttemptFailed {
            stage,
            marker,
            operation_failure,
            audit_failure,
        } => {
            assert_eq!(stage, AuthorityResetStage::SuccessAudit);
            assert_eq!(marker, MarkerPersistenceOutcome::Acknowledged);
            assert!(operation_failure.is_none());
            assert!(matches!(
                audit_failure.as_deref(),
                Some(AuthorityResetRefusal::AuditWriteFailed(_))
            ));
        }
        _ => panic!("missing acknowledgment context"),
    }
    assert_eq!(persistence_calls, 1);
    assert_eq!(publications, ["pending", "success"]);
    assert!(load_authority_state(&authority_state_file_path(dir.path()))
        .unwrap()
        .is_some());
    let audit: AuthorityResetAuditRecord =
        serde_json::from_slice(&std::fs::read(inputs.audit_output_path.unwrap()).unwrap()).unwrap();
    assert_eq!(audit.result, "pending");
}

#[test]
fn pending_audit_failure_never_invokes_persistence() {
    let dir = tempfile::tempdir().unwrap();
    let result = execute_verified_authority_reset(
        &inputs(dir.path()),
        plan(dir.path()),
        |_, _, _| {
            Err(AuthorityResetRefusal::AuditWriteFailed(
                "injected pending".into(),
            ))
        },
        |_, _| panic!("persistence must not be invoked"),
    )
    .unwrap_err();
    assert!(matches!(
        result,
        AuthorityResetRefusal::AttemptFailed {
            stage: AuthorityResetStage::PendingAudit,
            marker: MarkerPersistenceOutcome::NotAttempted,
            operation_failure: None,
            audit_failure: Some(_),
        }
    ));
    assert!(!authority_state_file_path(dir.path()).exists());
}
