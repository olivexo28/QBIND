//! Public reset acceptance controls with real verification and synthetic keys.
//! No private verified plan, operational key, network or signing service.

use std::fs;

use qbind_crypto::MlDsa44Backend;
use qbind_ledger::bundle_signing_ratification::test_helpers::build_signed_ratification;
use qbind_ledger::genesis::{
    GenesisAllocation, GenesisAuthorityConfig, GenesisAuthorityRoot, GenesisConfig,
    GenesisCouncilConfig, GenesisMonetaryConfig, GenesisValidator,
    GENESIS_AUTHORITY_SUITE_ML_DSA_44,
};
use qbind_ledger::{
    canonical_ratification_digest, compute_canonical_genesis_hash, NetworkEnvironmentPolicy,
    RatificationEnvironment,
};
use qbind_node::pqc_authority_state::{
    authority_state_file_path, canonical_authority_state_digest, load_authority_state,
    AuthorityStateUpdateSource,
};
use qbind_node::pqc_authority_state_reset::{
    execute_authority_state_reset, verify_authority_reset_inputs, AuthorityResetAuditRecord,
    AuthorityResetInputs, AuthorityResetRefusal,
};
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
use qbind_node::pqc_trust_bundle::{
    derive_signing_key_id, sign_bundle_devnet_helper, RootStatus, TrustBundle,
    TrustBundleEnvironment, TrustBundleRoot,
};
use qbind_node::pqc_trust_sequence::chain_id_hex;
use qbind_types::NetworkEnvironment;
use sha3::{Digest, Sha3_256};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
#[cfg(target_os = "linux")]
fn verified_synthetic_reset_success_tampering_and_path_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let (signing_pk, signing_sk) = MlDsa44Backend::generate_keypair().unwrap();
    let signing_id = derive_signing_key_id(&signing_pk);
    let (authority_pk, authority_sk) = MlDsa44Backend::generate_keypair().unwrap();
    let root = mint_devnet_root().unwrap();
    let chain = chain_id_hex(NetworkEnvironment::Devnet.chain_id());
    let authority = GenesisAuthorityConfig::new(vec![GenesisAuthorityRoot::with_public_key_bytes(
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        &authority_pk,
        "synthetic-reset-test",
    )]);
    let mut genesis = GenesisConfig::new(
        &chain,
        1_738_000_000_000,
        vec![GenesisAllocation::new(
            format!("0x{}", "11".repeat(32)),
            100,
        )],
        vec![GenesisValidator::new(
            format!("0x{}", "22".repeat(32)),
            "ab".repeat(32),
            100,
        )],
        GenesisCouncilConfig::new(
            vec![
                format!("0x{}", "33".repeat(32)),
                format!("0x{}", "44".repeat(32)),
                format!("0x{}", "55".repeat(32)),
            ],
            2,
        ),
        GenesisMonetaryConfig::mainnet_default(),
    );
    genesis.authority = Some(authority.clone());
    let genesis_hash = compute_canonical_genesis_hash(&genesis, NetworkEnvironmentPolicy::Devnet);
    let mut bundle = TrustBundle {
        bundle_version: TrustBundle::SUPPORTED_SCHEMA_VERSION,
        environment: TrustBundleEnvironment::Devnet,
        chain_id: Some(chain.clone()),
        generated_at: 100,
        valid_from: 0,
        valid_until: u64::MAX,
        sequence: 2,
        roots: vec![TrustBundleRoot {
            root_id: hex(&root.root_key_id),
            suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
            root_pk: hex(&root.root_pk),
            status: RootStatus::Active,
            not_before: 0,
            not_after: u64::MAX,
            activation_epoch: None,
            activation_height: None,
        }],
        revocations: Vec::new(),
        signature: None,
        activation_epoch: None,
        activation_height: None,
    };
    bundle.signature = Some(sign_bundle_devnet_helper(&bundle, signing_id, &signing_sk).unwrap());
    let mut ratification = build_signed_ratification(
        &chain,
        RatificationEnvironment::Devnet,
        genesis_hash,
        &hex(&authority_pk),
        &authority_sk,
        &signing_pk,
    );
    // Only public material and signatures are serialized; private keys stay in memory.
    let genesis_path = dir.path().join("genesis.json");
    let bundle_path = dir.path().join("bundle.json");
    let ratification_path = dir.path().join("ratification.json");
    fs::write(&genesis_path, serde_json::to_vec(&genesis).unwrap()).unwrap();
    fs::write(&bundle_path, serde_json::to_vec(&bundle).unwrap()).unwrap();
    fs::write(
        &ratification_path,
        serde_json::to_vec(&ratification).unwrap(),
    )
    .unwrap();
    let inputs = AuthorityResetInputs {
        data_dir: Some(dir.path().to_path_buf()),
        genesis_path: Some(genesis_path),
        expected_genesis_hash: Some(hex(&genesis_hash)),
        trust_bundle_path: Some(bundle_path.clone()),
        bundle_signing_key_specs: vec![format!(
            "{}:{}:{}",
            hex(&signing_id),
            PQC_TRANSPORT_SUITE_ML_DSA_44,
            hex(&signing_pk)
        )],
        ratification_path: Some(ratification_path.clone()),
        audit_output_path: Some(dir.path().join("audit.json")),
        environment: NetworkEnvironment::Devnet,
        operator_note: None,
        validation_time_secs: 300,
        updated_at_unix_secs: 1_700_000_000,
    };
    let marker_path = authority_state_file_path(dir.path());
    assert!(!marker_path.exists());
    let first_plan = verify_authority_reset_inputs(&inputs).expect("real verification");
    assert!(!first_plan.old_marker_archive.present);
    assert!(!marker_path.exists(), "verifier must not persist");
    let first = execute_authority_state_reset(&inputs).expect("public reset succeeds");
    let marker = load_authority_state(&marker_path).unwrap().unwrap();
    assert_eq!(marker, first_plan.new_marker);
    assert_eq!(marker.chain_id, chain);
    assert_eq!(marker.environment, TrustBundleEnvironment::Devnet);
    assert_eq!(marker.genesis_hash, hex(&genesis_hash));
    assert_eq!(
        marker.authority_policy_version,
        authority.authority_policy_version
    );
    assert_eq!(marker.authority_sequence, authority.authority_sequence);
    assert_eq!(marker.authority_epoch, authority.authority_epoch);
    assert_eq!(marker.authority_root_fingerprint, hex(&authority_pk));
    assert_eq!(
        marker.ratified_bundle_signing_key_fingerprint,
        hex(&Sha3_256::digest(&signing_pk))
    );
    assert_eq!(
        marker.ratification_object_hash,
        hex(&canonical_ratification_digest(&ratification))
    );
    assert_eq!(
        marker.last_update_source,
        AuthorityStateUpdateSource::OperatorReset
    );
    assert_eq!(marker.updated_at_unix_secs, inputs.updated_at_unix_secs);
    assert_eq!(first.marker_path, marker_path);
    assert_eq!(
        first.new_marker_hash_hex,
        hex(&canonical_authority_state_digest(&marker))
    );
    let audit_path = inputs.audit_output_path.as_ref().unwrap();
    let first_audit: AuthorityResetAuditRecord =
        serde_json::from_slice(&fs::read(audit_path).unwrap()).unwrap();
    assert_eq!(first_audit.result, "success");
    assert_eq!(first_audit.environment, "devnet");
    assert_eq!(first_audit.chain_id.as_ref(), Some(&marker.chain_id));
    assert_eq!(
        first_audit.trust_bundle_fingerprint.as_ref(),
        Some(&first_plan.trust_bundle_fingerprint_hex)
    );
    assert_eq!(first_audit.new_marker_record.as_ref(), Some(&marker));
    assert_eq!(
        first_audit.new_marker_hash.as_ref(),
        Some(&first.new_marker_hash_hex)
    );
    assert_eq!(
        first_audit.genesis_hash.as_deref(),
        Some(hex(&genesis_hash).as_str())
    );
    assert_eq!(
        first_audit.ratification_hash.as_deref(),
        Some(marker.ratification_object_hash.as_str())
    );
    assert!(first_audit.refusal_reason_if_any.is_none());
    assert!(first_audit.refusal_detail_if_any.is_none());
    assert!(!first.old_marker_archive.present);
    println!("first reset: public success; loader/derived fields/final audit consistent");

    // A second fully verified reset exercises existing-marker archival as well.
    let before = fs::read(&marker_path).unwrap();
    let repeat_plan = verify_authority_reset_inputs(&inputs).unwrap();
    let repeat = execute_authority_state_reset(&inputs).unwrap();
    let repeat_audit: AuthorityResetAuditRecord =
        serde_json::from_slice(&fs::read(audit_path).unwrap()).unwrap();
    assert!(repeat.old_marker_archive.present);
    assert_eq!(repeat.old_marker_archive.parsed.as_ref(), Some(&marker));
    assert_eq!(
        repeat_audit.old_marker_record_if_parseable.as_ref(),
        Some(&marker)
    );
    assert_eq!(
        repeat_audit.old_marker_raw_sha256,
        Some(hex(&Sha3_256::digest(&before)))
    );
    assert_eq!(
        repeat_audit.new_marker_record.as_ref(),
        Some(&repeat_plan.new_marker)
    );
    assert_eq!(
        repeat_audit.new_marker_hash.as_ref(),
        Some(&repeat.new_marker_hash_hex)
    );
    assert_eq!(repeat_audit.result, "success");
    assert_eq!(fs::read(&marker_path).unwrap(), before);
    println!("repeat reset: verified existing-marker success; archive and final audit consistent");

    let success_audit = fs::read(audit_path).unwrap();
    let mut collision = inputs.clone();
    collision.audit_output_path = Some(marker_path.clone());
    assert!(
        verify_authority_reset_inputs(&collision).is_ok(),
        "inputs otherwise valid"
    );
    assert!(matches!(
        execute_authority_state_reset(&collision),
        Err(AuthorityResetRefusal::UnsafeAuditPath(_))
    ));
    assert_eq!(fs::read(&marker_path).unwrap(), before);
    assert_eq!(fs::read(audit_path).unwrap(), success_audit);
    assert!(load_authority_state(&marker_path).unwrap().is_some());
    println!(
        "valid-input equal path: UnsafeAuditPath at pre-verification guard; marker/audit unchanged"
    );

    // Changing signed content without re-signing must fail actual bundle verification.
    bundle.sequence += 1;
    fs::write(&bundle_path, serde_json::to_vec(&bundle).unwrap()).unwrap();
    assert!(matches!(
        verify_authority_reset_inputs(&inputs),
        Err(AuthorityResetRefusal::InvalidTrustBundle(_))
    ));
    assert!(matches!(
        execute_authority_state_reset(&inputs),
        Err(AuthorityResetRefusal::InvalidTrustBundle(_))
    ));
    assert_eq!(fs::read(&marker_path).unwrap(), before);
    let refused: AuthorityResetAuditRecord =
        serde_json::from_slice(&fs::read(audit_path).unwrap()).unwrap();
    assert_eq!(refused.result, "refused");
    assert_eq!(
        refused.refusal_reason_if_any.as_deref(),
        Some("InvalidTrustBundle")
    );
    assert!(refused.new_marker_record.is_none());
    println!("tampered signed bundle: real verification refusal; marker unchanged; separate refusal audit");

    bundle.sequence -= 1;
    fs::write(&bundle_path, serde_json::to_vec(&bundle).unwrap()).unwrap();
    ratification.signature[0] ^= 1;
    fs::write(
        &ratification_path,
        serde_json::to_vec(&ratification).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        verify_authority_reset_inputs(&inputs),
        Err(AuthorityResetRefusal::RatificationEnforcementFailed(_))
    ));
    assert!(matches!(
        execute_authority_state_reset(&inputs),
        Err(AuthorityResetRefusal::RatificationEnforcementFailed(_))
    ));
    assert_eq!(fs::read(&marker_path).unwrap(), before);
    assert!(load_authority_state(&marker_path).unwrap().is_some());
    let refused: AuthorityResetAuditRecord =
        serde_json::from_slice(&fs::read(audit_path).unwrap()).unwrap();
    assert_eq!(refused.result, "refused");
    assert_eq!(
        refused.refusal_reason_if_any.as_deref(),
        Some("RatificationEnforcementFailed")
    );
    assert!(refused.new_marker_record.is_none());
    println!("tampered ratification signature: Strict enforcement refusal; marker unchanged; separate refusal audit");
    dir.close().unwrap();
}
