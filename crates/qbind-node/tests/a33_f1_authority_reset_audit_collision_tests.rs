//! Baseline reproductions, not fixes: actual reset code and synthetic files only.
//! Equal lexical paths are tested; aliases, durability and startup are not.

use std::fs;

use qbind_node::pqc_authority_state::{
    authority_state_file_path, load_authority_state, AuthorityStateUpdateSource,
    PersistentAuthorityStateRecord,
};
use qbind_node::pqc_authority_state_reset::{
    execute_authority_state_reset, verify_authority_reset_inputs, AuthorityResetAuditRecord,
    AuthorityResetInputs, AuthorityResetRefusal,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;
use qbind_types::NetworkEnvironment;

fn investigate_refusal(audit_equals_marker: bool) {
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

    let audit_path = if audit_equals_marker {
        marker_path.clone()
    } else {
        dir.path().join("reset-audit.json")
    };
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

    let result = execute_authority_state_reset(&inputs);
    let after = fs::read(&marker_path).unwrap();
    let audit_bytes = fs::read(&audit_path).expect("refusal audit must exist");
    println!("audit_equals_marker={audit_equals_marker}; returned={result:?}");
    println!("marker_before={}", String::from_utf8_lossy(&before));
    println!("marker_after={}", String::from_utf8_lossy(&after));
    println!("audit_bytes={}", String::from_utf8_lossy(&audit_bytes));
    println!("marker_bytes_changed={}", before != after);
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

    if audit_equals_marker {
        assert_ne!(after, before, "baseline collision must be reproduced");
        assert_eq!(after, audit_bytes);
        assert!(
            load_authority_state(&marker_path).is_err(),
            "refusal audit has replaced the previously parseable marker"
        );
    } else {
        assert_eq!(after, before, "distinct audit path preserves marker bytes");
        assert!(load_authority_state(&marker_path).unwrap().is_some());
        assert_ne!(after, audit_bytes);
    }
    assert!(!audit_path.with_extension("json.tmp").exists());
    dir.close()
        .expect("remove only this test's temporary files");
}

#[test]
fn refusal_audit_at_marker_path_replaces_synthetic_marker_baseline() {
    investigate_refusal(true);
}

#[test]
fn refusal_audit_at_distinct_path_preserves_synthetic_marker_control() {
    investigate_refusal(false);
}
