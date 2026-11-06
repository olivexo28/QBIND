#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use qbind_crypto::MlDsa44Backend;
use qbind_ledger::bundle_signing_ratification::test_helpers::build_signed_ratification;
use qbind_ledger::genesis::{
    GenesisAllocation, GenesisAuthorityConfig, GenesisAuthorityRoot, GenesisConfig,
    GenesisCouncilConfig, GenesisMonetaryConfig, GenesisValidator,
    GENESIS_AUTHORITY_SUITE_ML_DSA_44,
};
use qbind_ledger::{
    compute_canonical_genesis_hash, NetworkEnvironmentPolicy, RatificationEnvironment,
};
use qbind_node::pqc_authority_state::{authority_state_file_path, load_authority_state};
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// Same verified synthetic ceremony as the retained successful-reset fixture.
fn verified_inputs(dir: &Path) -> AuthorityResetInputs {
    let (signing_pk, signing_sk) = MlDsa44Backend::generate_keypair().unwrap();
    let signing_id = derive_signing_key_id(&signing_pk);
    let (authority_pk, authority_sk) = MlDsa44Backend::generate_keypair().unwrap();
    let root = mint_devnet_root().unwrap();
    let chain = chain_id_hex(NetworkEnvironment::Devnet.chain_id());
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
    genesis.authority = Some(GenesisAuthorityConfig::new(vec![
        GenesisAuthorityRoot::with_public_key_bytes(
            GENESIS_AUTHORITY_SUITE_ML_DSA_44,
            &authority_pk,
            "synthetic-reset-test",
        ),
    ]));
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
    let ratification = build_signed_ratification(
        &chain,
        RatificationEnvironment::Devnet,
        genesis_hash,
        &hex(&authority_pk),
        &authority_sk,
        &signing_pk,
    );
    let genesis_path = dir.join("genesis.json");
    let bundle_path = dir.join("bundle.json");
    let ratification_path = dir.join("ratification.json");
    fs::write(&genesis_path, serde_json::to_vec(&genesis).unwrap()).unwrap();
    fs::write(&bundle_path, serde_json::to_vec(&bundle).unwrap()).unwrap();
    fs::write(
        &ratification_path,
        serde_json::to_vec(&ratification).unwrap(),
    )
    .unwrap();
    AuthorityResetInputs {
        data_dir: Some(dir.to_path_buf()),
        genesis_path: Some(genesis_path),
        expected_genesis_hash: Some(hex(&genesis_hash)),
        trust_bundle_path: Some(bundle_path),
        bundle_signing_key_specs: vec![format!(
            "{}:{}:{}",
            hex(&signing_id),
            PQC_TRANSPORT_SUITE_ML_DSA_44,
            hex(&signing_pk)
        )],
        ratification_path: Some(ratification_path),
        audit_output_path: Some(dir.join("audit.json")),
        environment: NetworkEnvironment::Devnet,
        operator_note: None,
        validation_time_secs: 300,
        updated_at_unix_secs: 1_700_000_000,
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Entry {
    name: PathBuf,
    identity: (u64, u64),
    links: u64,
    bytes: Vec<u8>,
}

fn entries(dir: &Path) -> Vec<Entry> {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let metadata = fs::symlink_metadata(entry.path()).unwrap();
            assert!(metadata.is_file());
            Entry {
                name: entry.file_name().into(),
                identity: (metadata.dev(), metadata.ino()),
                links: metadata.nlink(),
                bytes: fs::read(entry.path()).unwrap(),
            }
        })
        .collect();
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    entries
}

#[test]
fn marker_temp_identity_refuses_and_distinct_files_allow_verified_reset() {
    let dir = tempfile::tempdir().unwrap();
    let mut inputs = verified_inputs(dir.path());
    // The public API requires caller-owned destination ownership.
    let lock = qbind_node::restore_completion::acquire_destination_lock(dir.path()).unwrap();
    let marker = authority_state_file_path(dir.path());
    let temporary = dir.path().join("pqc_authority_state.json.tmp");
    let audit = inputs.audit_output_path.as_ref().unwrap().clone();
    let audit_tmp = audit.with_extension("json.tmp");
    verify_authority_reset_inputs(&inputs).expect("real signed-input verification");
    execute_authority_state_reset(&inputs).expect("establish valid existing marker");
    let original = load_authority_state(&marker).unwrap().unwrap();
    fs::remove_file(&audit).unwrap();
    fs::hard_link(&marker, &temporary).unwrap();
    inputs.updated_at_unix_secs += 1;
    let plan = verify_authority_reset_inputs(&inputs).expect("hard-link inputs otherwise valid");
    assert_ne!(plan.new_marker, original);
    let before = entries(dir.path());
    let marker_before = before
        .iter()
        .find(|entry| entry.name == Path::new("pqc_authority_state.json"))
        .unwrap();
    let temp_before = before
        .iter()
        .find(|entry| entry.name == Path::new("pqc_authority_state.json.tmp"))
        .unwrap();
    assert_eq!(marker_before.identity, temp_before.identity);
    assert_eq!(marker_before.bytes, temp_before.bytes);
    assert_eq!(marker_before.links, 2);
    assert!(!audit.exists());
    assert!(!audit_tmp.exists());

    let result = execute_authority_state_reset(&inputs);
    if std::env::var_os("QBIND_I1_BASELINE").is_some() {
        result.expect("starting revision accepts marker/temp hard link");
        let changed = fs::read(&marker).unwrap();
        assert_ne!(changed, marker_before.bytes);
        assert_eq!(
            load_authority_state(&marker).unwrap(),
            Some(plan.new_marker)
        );
        let metadata = fs::metadata(&marker).unwrap();
        assert_eq!((metadata.dev(), metadata.ino()), marker_before.identity);
        assert_eq!(metadata.nlink(), 2);
        assert_eq!(fs::read(&temporary).unwrap(), changed);
        let temporary_metadata = fs::metadata(&temporary).unwrap();
        assert_eq!(
            (temporary_metadata.dev(), temporary_metadata.ino()),
            marker_before.identity
        );
        assert!(!audit_tmp.exists());
        let published: AuthorityResetAuditRecord =
            serde_json::from_slice(&fs::read(&audit).unwrap()).unwrap();
        assert_eq!(published.result, "success");
        println!("BASELINE ONLY: public reset accepted verified hard-link fixture; marker/temp bytes changed on original shared inode; rename retained both hard-link names; success audit published");
    } else {
        assert!(matches!(
            result,
            Err(AuthorityResetRefusal::UnsafeAuditPath(_))
        ));
        assert_eq!(entries(dir.path()), before);
        assert_eq!(load_authority_state(&marker).unwrap(), Some(original));
        println!("CORRECTED: UnsafeAuditPath; every directory entry, inode, link count and file byte unchanged; no audit final/temp publication");
        fs::remove_file(&temporary).unwrap();
        fs::write(&temporary, b"distinct stale temporary file").unwrap();
        assert_ne!(
            fs::metadata(&marker).unwrap().ino(),
            fs::metadata(&temporary).unwrap().ino()
        );
        verify_authority_reset_inputs(&inputs).expect("distinct-file inputs valid");
        execute_authority_state_reset(&inputs).expect("distinct marker/temp files allowed");
        assert_eq!(
            load_authority_state(&marker).unwrap(),
            Some(plan.new_marker)
        );
        assert!(!temporary.exists());
        assert!(!audit_tmp.exists());
        let published: AuthorityResetAuditRecord =
            serde_json::from_slice(&fs::read(&audit).unwrap()).unwrap();
        assert_eq!(published.result, "success");
        println!("CONTROL: distinct marker/temp files; verified public reset succeeds; expected marker and success audit retained");
    }
    drop(lock);
    dir.close().unwrap();
}
