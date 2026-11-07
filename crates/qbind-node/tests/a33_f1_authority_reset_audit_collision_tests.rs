//! Corrected collision controls using actual reset code and synthetic files.
//! Historical baseline bytes are preserved in task evidence.

#![cfg(target_os = "linux")]

use std::fs;

use qbind_node::pqc_authority_state::{
    authority_state_file_path, load_authority_state, AuthorityStateUpdateSource,
    PersistentAuthorityStateRecord,
};
use qbind_node::pqc_authority_state_reset::{
    build_refusal_audit_record, execute_authority_state_reset, verify_authority_reset_inputs,
    write_authority_reset_audit, AuthorityResetAuditRecord, AuthorityResetInputs,
    AuthorityResetRefusal,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;
use qbind_types::NetworkEnvironment;

fn snapshot(dir: &std::path::Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let meta = fs::symlink_metadata(&path).unwrap();
        let bytes = if meta.is_file() {
            fs::read(&path).unwrap()
        } else if meta.file_type().is_symlink() {
            fs::read_link(&path)
                .unwrap()
                .as_os_str()
                .as_encoded_bytes()
                .to_vec()
        } else {
            entries.extend(snapshot(&path));
            Vec::new()
        };
        entries.push((path, bytes));
    }
    entries.sort();
    entries
}

fn investigate_refusal(case: &str) {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("isolated synthetic data directory");
    let marker_path = authority_state_file_path(dir.path());
    let marker = PersistentAuthorityStateRecord::new(
        "0000000000000001".to_string(),
        TrustBundleEnvironment::Devnet,
        "a".repeat(64),
        1,
        5,
        Some(2),
        "b".repeat(40),
        "c".repeat(40),
        "d".repeat(64),
        AuthorityStateUpdateSource::TestOrFixture,
        1_700_000_000,
    );
    let before = serde_json::to_vec_pretty(&marker).unwrap();
    fs::write(&marker_path, &before).unwrap();
    assert_eq!(load_authority_state(&marker_path).unwrap(), Some(marker));

    let distinct = dir.path().join("reset-audit.json");
    let marker_tmp = dir.path().join("pqc_authority_state.json.tmp");
    let audit_path = match case {
        "equal" => marker_path.clone(),
        "dot" => dir.path().join(".").join("pqc_authority_state.json"),
        "parent" => {
            fs::create_dir(dir.path().join("child")).unwrap();
            dir.path().join("child/../pqc_authority_state.json")
        }
        "marker-temp" => {
            fs::write(&marker_tmp, b"existing marker temporary bytes").unwrap();
            marker_tmp.clone()
        }
        "derived-marker-temp" => dir.path().join("pqc_authority_state.audit"),
        "audit-temp-alias" => {
            fs::hard_link(&marker_path, distinct.with_extension("json.tmp")).unwrap();
            distinct.clone()
        }
        "hard-link" => {
            fs::hard_link(&marker_path, &distinct).unwrap();
            distinct.clone()
        }
        "marker-temp-alias" => {
            fs::write(&marker_tmp, b"existing marker temporary bytes").unwrap();
            fs::hard_link(&marker_tmp, distinct.with_extension("json.tmp")).unwrap();
            distinct.clone()
        }
        "parent-symlink" | "distinct-parent-symlink" => {
            symlink(dir.path(), dir.path().join("alias")).unwrap();
            dir.path().join("alias").join(if case == "parent-symlink" {
                "pqc_authority_state.json"
            } else {
                "reset-audit.json"
            })
        }
        "leaf-symlink" => {
            symlink(&marker_path, &distinct).unwrap();
            distinct.clone()
        }
        "dangling-parent" => {
            symlink(dir.path().join("absent"), dir.path().join("alias")).unwrap();
            dir.path().join("alias/audit.json")
        }
        "loop-parent" => {
            symlink("alias", dir.path().join("alias")).unwrap();
            dir.path().join("alias/audit.json")
        }
        "missing-parent" => dir.path().join("absent/audit.json"),
        "non-directory-parent" => marker_path.join("audit.json"),
        "special-leaf" => {
            fs::create_dir(&distinct).unwrap();
            distinct.clone()
        }
        "distinct" => distinct.clone(),
        "recheck" => {
            fs::create_dir(dir.path().join("audit-only")).unwrap();
            symlink(dir.path().join("audit-only"), dir.path().join("alias")).unwrap();
            dir.path().join("alias/pqc_authority_state.json")
        }
        _ => panic!("unknown test case"),
    };
    let marker_tmp_before = fs::read(&marker_tmp).ok();
    let safe = matches!(case, "distinct" | "distinct-parent-symlink" | "recheck");
    let inputs = AuthorityResetInputs {
        data_dir: Some(dir.path().to_path_buf()),
        genesis_path: Some(dir.path().join("unused-genesis.json")),
        expected_genesis_hash: Some("not-a-genesis-hash".to_string()),
        trust_bundle_path: Some(dir.path().join("unused-bundle.json")),
        bundle_signing_key_specs: Vec::new(),
        ratification_path: Some(dir.path().join("unused-ratification.json")),
        audit_output_path: Some(audit_path.clone()),
        environment: NetworkEnvironment::Devnet,
        operator_note: None,
        validation_time_secs: 0,
        updated_at_unix_secs: 0,
    };
    let verification = verify_authority_reset_inputs(&inputs).unwrap_err();
    assert!(matches!(
        verification,
        AuthorityResetRefusal::MalformedExpectedGenesisHash(_)
    ));
    assert_eq!(fs::read(&marker_path).unwrap(), before);

    let namespace_before = snapshot(dir.path());
    let result = execute_authority_state_reset(&inputs);
    let after = fs::read(&marker_path).unwrap();
    println!("case={case}; returned={result:?}");
    println!("marker_before={}", String::from_utf8_lossy(&before));
    println!("marker_after={}", String::from_utf8_lossy(&after));
    println!("marker_bytes_changed={}", before != after);
    assert_eq!(after, before, "all controls must preserve the marker");
    assert!(load_authority_state(&marker_path).unwrap().is_some());
    assert_eq!(fs::read(&marker_tmp).ok(), marker_tmp_before);
    if !safe {
        assert!(matches!(
            result,
            Err(AuthorityResetRefusal::UnsafeAuditPath(_))
        ));
        let mut record = build_refusal_audit_record(&inputs, None, &verification);
        for state in ["pending", "refused", "success"] {
            record.result = state.to_string();
            assert!(matches!(
                write_authority_reset_audit(dir.path(), &audit_path, &record),
                Err(AuthorityResetRefusal::UnsafeAuditPath(_))
            ));
        }
        assert_eq!(
            snapshot(dir.path()),
            namespace_before,
            "no publication on refusal"
        );
        assert_eq!(fs::read(&marker_path).unwrap(), before);
        assert_eq!(fs::read(&marker_tmp).ok(), marker_tmp_before);
        if matches!(case, "missing-parent" | "dangling-parent") {
            assert!(!dir.path().join("absent").exists());
        }
        if case == "audit-temp-alias" {
            assert_eq!(
                fs::read(distinct.with_extension("json.tmp")).unwrap(),
                before
            );
            assert!(!distinct.exists());
        }
        dir.close().unwrap();
        return;
    }
    let audit_bytes = fs::read(&audit_path).expect("safe refusal audit must exist");
    println!("audit_bytes={}", String::from_utf8_lossy(&audit_bytes));
    assert_eq!(result.unwrap_err(), verification);
    let audit: AuthorityResetAuditRecord = serde_json::from_slice(&audit_bytes).unwrap();
    assert_eq!(audit.result, "refused");
    assert_eq!(
        audit.refusal_reason_if_any.as_deref(),
        Some("MalformedExpectedGenesisHash")
    );
    assert!(audit.new_marker_record.is_none());
    assert!(audit.new_marker_hash.is_none());
    assert_eq!(audit.to_canonical_json().unwrap(), audit_bytes);

    assert_ne!(after, audit_bytes);
    assert!(!audit_path.with_extension("json.tmp").exists());
    if case == "recheck" {
        fs::remove_file(dir.path().join("alias")).unwrap();
        symlink(dir.path(), dir.path().join("alias")).unwrap();
        let before_recheck = snapshot(dir.path());
        for state in ["pending", "refused", "success"] {
            let mut record = audit.clone();
            record.result = state.to_string();
            assert!(matches!(
                write_authority_reset_audit(dir.path(), &audit_path, &record),
                Err(AuthorityResetRefusal::UnsafeAuditPath(_))
            ));
        }
        assert_eq!(snapshot(dir.path()), before_recheck);
    }
    dir.close()
        .expect("remove only this test's temporary files");
}

#[test]
fn refusal_audit_at_marker_path_is_rejected_without_marker_change() {
    investigate_refusal("equal");
}

#[test]
fn refusal_audit_at_distinct_path_preserves_synthetic_marker_control() {
    investigate_refusal("distinct");
}

#[test]
fn equivalent_spellings_and_temporary_aliases_refuse() {
    for case in [
        "dot",
        "parent",
        "marker-temp",
        "derived-marker-temp",
        "audit-temp-alias",
        "hard-link",
        "marker-temp-alias",
    ] {
        investigate_refusal(case);
    }
}

#[test]
fn parent_symlinks_resolve_but_leaf_symlinks_refuse() {
    for case in ["parent-symlink", "distinct-parent-symlink", "leaf-symlink"] {
        investigate_refusal(case);
    }
}

#[test]
fn unavailable_or_unsupported_paths_refuse_without_publication() {
    for case in [
        "missing-parent",
        "dangling-parent",
        "loop-parent",
        "non-directory-parent",
        "special-leaf",
    ] {
        investigate_refusal(case);
    }
}

#[test]
fn publication_rechecks_parent_alias_after_an_earlier_safe_write() {
    investigate_refusal("recheck");
}
