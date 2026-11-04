use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_gov::{sign_envelope, CouncilKey, CouncilKeySet, EnvelopeError, UpgradeEnvelope};
use std::path::Path;
use std::process::{Command, Output};

fn fixture() -> (UpgradeEnvelope, CouncilKeySet) {
    let mut envelope = UpgradeEnvelope::from_json(
        r#"{"envelope_version":"1.0","envelope_id":"F002-disposable",
        "protocol_version":"0.1.0","network_environment":"test",
        "class":"c_hard_fork","activation_height":1,
        "binary_hashes":{"linux-x86_64":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}"#,
    )
    .unwrap();
    let mut keys = Vec::new();
    for id in ["a", "b", "c"] {
        let (pk, sk) = MlDsa44Backend::generate_keypair().unwrap();
        let pk = hex::encode(pk);
        assert!(keys.iter().all(|key: &CouncilKey| key.public_key != pk));
        envelope
            .council_approvals
            .push(sign_envelope(&envelope, id, &pk, &sk).unwrap());
        keys.push(CouncilKey::new(id, pk));
    }
    let keyset = CouncilKeySet::new(2, keys);
    keyset.validate().unwrap();
    envelope.validate().unwrap();
    (envelope, keyset)
}

fn write_inputs(dir: &Path, envelope: &UpgradeEnvelope, keyset: &CouncilKeySet) {
    std::fs::write(
        dir.join("envelope.json"),
        envelope.to_json_pretty().unwrap(),
    )
    .unwrap();
    std::fs::write(dir.join("keys.json"), keyset.to_json_pretty().unwrap()).unwrap();
}

fn verify(dir: &Path, json: bool, binary: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_qbind-envelope"));
    command
        .arg("verify")
        .arg("--envelope")
        .arg(dir.join("envelope.json"))
        .arg("--council-keys")
        .arg(dir.join("keys.json"));
    if json {
        command.args(["--output", "json"]);
    }
    if binary {
        command.arg("--binary").arg(dir.join("does-not-exist"));
    }
    command.output().unwrap()
}

fn assert_error(output: Output, code: i32, diagnostic: &str) {
    assert_eq!(output.status.code(), Some(code));
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    assert_eq!(output.stderr, diagnostic.as_bytes());
}

#[test]
fn f002_cli_duplicate_text_json_and_binary_early_return() {
    let (full, keyset) = fixture();
    let dir = tempfile::tempdir().unwrap();
    let mut different = full.council_approvals[0].clone();
    different.signature = "not hex".into();
    different.timestamp = "different".into();
    let mut unknown = different.clone();
    unknown.member_id = "unknown".into();
    for (approvals, id) in [
        (vec![full.council_approvals[0].clone(); 2], "a"),
        (vec![full.council_approvals[0].clone(), different], "a"),
        (
            vec![
                full.council_approvals[1].clone(),
                full.council_approvals[0].clone(),
                full.council_approvals[0].clone(),
                full.council_approvals[1].clone(),
            ],
            "a",
        ),
        (
            [
                full.council_approvals.clone(),
                vec![unknown.clone(), unknown],
            ]
            .concat(),
            "unknown",
        ),
    ] {
        let mut envelope = full.clone();
        envelope.council_approvals = approvals;
        envelope.validate().unwrap();
        write_inputs(dir.path(), &envelope, &keyset);
        for json in [false, true] {
            for binary in [false, true] {
                assert_error(
                    verify(dir.path(), json, binary),
                    1,
                    &format!("Error during verification: verification failed: duplicate approval member_id: {id}\n"),
                );
            }
        }
    }
}

#[test]
fn f002_cli_nonduplicate_controls_schema_and_invalid_extra() {
    let (full, keyset) = fixture();
    let dir = tempfile::tempdir().unwrap();
    for (count, invalid_extra) in [(0, false), (1, false), (2, false), (2, true)] {
        let mut envelope = full.clone();
        envelope.council_approvals.truncate(count);
        if invalid_extra {
            let mut extra = full.council_approvals[2].clone();
            extra.signature = "not hex".into();
            envelope.council_approvals.push(extra);
        }
        write_inputs(dir.path(), &envelope, &keyset);
        for json in [false, true] {
            let output = verify(dir.path(), json, false);
            assert_eq!(output.status.code(), Some(if count >= 2 { 0 } else { 1 }));
            assert!(output.stderr.is_empty());
            if json {
                let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
                let object = result.as_object().unwrap();
                assert_eq!(
                    object.keys().map(String::as_str).collect::<Vec<_>>(),
                    [
                        "binary_hash_ok",
                        "digest_hex",
                        "signatures",
                        "threshold",
                        "valid",
                        "valid_count"
                    ]
                );
                assert_eq!(result["valid"], count >= 2);
                assert_eq!(result["valid_count"], count);
                assert_eq!(result["threshold"], 2);
                assert_eq!(result["binary_hash_ok"], serde_json::Value::Null);
                assert_eq!(
                    result["digest_hex"],
                    qbind_gov::envelope_digest_hex(&envelope).unwrap()
                );
                let signatures = result["signatures"].as_array().unwrap();
                assert_eq!(signatures.len(), count + usize::from(invalid_extra));
                for (i, signature) in signatures.iter().enumerate() {
                    assert_eq!(
                        signature
                            .as_object()
                            .unwrap()
                            .keys()
                            .map(String::as_str)
                            .collect::<Vec<_>>(),
                        ["error", "member_id", "valid"]
                    );
                    assert_eq!(
                        signature["member_id"],
                        envelope.council_approvals[i].member_id
                    );
                    assert_eq!(signature["valid"], i < count);
                    if i < count {
                        assert!(signature["error"].is_null());
                    } else {
                        assert!(signature["error"]
                            .as_str()
                            .unwrap()
                            .starts_with("invalid signature hex:"));
                    }
                }
            } else {
                let text = String::from_utf8(output.stdout).unwrap();
                assert!(text.contains(&format!(
                    "Signatures:         {count}/{} valid (threshold: 2)",
                    envelope.approval_count()
                )));
                assert!(text.contains(if count >= 2 {
                    "=== VERIFICATION PASSED ==="
                } else {
                    "=== VERIFICATION FAILED ==="
                }));
                if invalid_extra {
                    assert!(text.contains("invalid signature hex:"));
                }
            }
        }
    }
    write_inputs(dir.path(), &full, &keyset);
    let output = verify(dir.path(), true, true);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .starts_with("Error computing binary hash:"));
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["binary_hash_ok"], false);
    assert_eq!(result["valid"], false);
}

#[test]
fn f002_cli_keyset_and_envelope_validation_precedence() {
    let (mut envelope, keyset) = fixture();
    envelope
        .council_approvals
        .push(envelope.council_approvals[0].clone());
    envelope.protocol_version.clear();
    let mut invalid_keysets = vec![keyset.clone(); 6];
    invalid_keysets[0].threshold = 0;
    invalid_keysets[1].threshold = 4;
    invalid_keysets[2].keys[1].member_id = "a".into();
    invalid_keysets[3].keys[0].public_key = "not hex".into();
    invalid_keysets[4].keyset_version = "unsupported".into();
    invalid_keysets[5].keys[0].public_key = "aa".into();
    let dir = tempfile::tempdir().unwrap();
    for invalid in invalid_keysets {
        let error = invalid.validate().unwrap_err();
        write_inputs(dir.path(), &envelope, &invalid);
        for json in [false, true] {
            assert_error(
                verify(dir.path(), json, true),
                2,
                &format!("Error: invalid council keyset: {error}\n"),
            );
        }
    }
    write_inputs(dir.path(), &envelope, &keyset);
    assert!(matches!(
        envelope.validate(),
        Err(EnvelopeError::MissingField(_))
    ));
    for json in [false, true] {
        assert_error(
            verify(dir.path(), json, true),
            1,
            "Error: invalid envelope structure: missing required field: protocol_version\n",
        );
    }
}

#[test]
fn f002_cli_inspect_is_descriptive_not_authorization() {
    let (mut envelope, keyset) = fixture();
    envelope.council_approvals = vec![envelope.council_approvals[0].clone(); 2];
    let dir = tempfile::tempdir().unwrap();
    write_inputs(dir.path(), &envelope, &keyset);
    let output = Command::new(env!("CARGO_BIN_EXE_qbind-envelope"))
        .arg("inspect")
        .arg(dir.path().join("envelope.json"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Council Approvals:  2 signature(s)"));
    assert_eq!(text.matches("  - a (").count(), 2);
    assert!(text.contains("Structure validation passed"));
    assert!(!text.contains("VERIFICATION PASSED"));
    assert_error(
        verify(dir.path(), false, false),
        1,
        "Error during verification: verification failed: duplicate approval member_id: a\n",
    );
}
