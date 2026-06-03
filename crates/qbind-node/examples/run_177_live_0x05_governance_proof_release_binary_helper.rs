//! Run 177 — release-built fixture helper that mints a complete
//! proof-carrying / no-proof / malformed / invalid-binding corpus for
//! the **release-binary live inbound `0x05` peer-candidate** evidence
//! harness. Consumed by
//! `scripts/devnet/run_177_live_0x05_governance_proof_release_binary.sh`
//! together with the **real `target/release/qbind-node`**.
//!
//! Run 177 closes the Run 176-deferred release-binary boundary by
//! supplying:
//!
//!   * a Run 076 `PeerCandidateEnvelope` JSON that the binary's
//!     **send-side** Run 080 publish path (`--p2p-trust-bundle-peer-
//!     candidate-wire-publish-path`) loads and the binary's
//!     `from_run076_envelope` bridge promotes to a Run 078 wire
//!     envelope;
//!   * a sibling `GovernanceAuthorityProofWire` JSON consumed by the
//!     Run 177 hidden harness-only flag
//!     `--p2p-trust-bundle-peer-candidate-wire-publish-governance-proof-path`,
//!     which is attached as the additive Run 176
//!     `governance_authority_proof` field on the wire envelope before
//!     [`encode_peer_candidate_wire_frame`] runs (no envelope schema
//!     change, no domain-tag bump);
//!   * a v2 ratification sidecar (no-proof and proof-carrying variants)
//!     for the receiver's `--p2p-trust-bundle-ratification` (Run 130
//!     verifier + Run 167/168 carrier);
//!   * a seeded v2@seq=1 authority marker (`pqc_authority_state.json`)
//!     so the receiver's Run 134/138 marker compare is well-defined.
//!
//! Per `task/RUN_177_TASK.txt`, Run 177 is **release-binary EVIDENCE
//! only**: this helper is fixture-tooling and does NOT modify any
//! production runtime code or wire format. All minted key material is
//! ephemeral. No production source-code anchor, fallback root, or
//! fallback signing key is introduced. No MainNet peer-driven apply is
//! enabled. No envelope schema change beyond the Run 176 additive
//! optional `governance_authority_proof` field.
//!
//! The helper writes the following files under `<OUT_DIR>/devnet/`:
//!
//!   * `genesis.json`                                - DevNet genesis
//!   * `expected-genesis-hash.txt`                   - canonical hash
//!   * `signing-key.ratified.spec`                   - active `--p2p-trust-bundle-signing-key`
//!   * `signing-key.rotated.spec`                    - rotated `--p2p-trust-bundle-signing-key`
//!   * `baseline.bundle`                             - signed seq=1 trust bundle
//!   * `candidate.bundle`                            - signed seq=2 trust bundle (active)
//!   * `candidate.rotated.bundle`                    - signed seq=2 trust bundle (rotated)
//!   * `seed-marker.v2.seq1.json`                    - prior v2@seq=1 marker
//!   * `peer-candidate.candidate.json`               - Run 076 envelope wrapping `candidate.bundle`
//!     (used for the legacy/no-proof Ratify@seq=1 A1 scenario)
//!   * `peer-candidate.rotated.json`                 - Run 076 envelope wrapping `candidate.rotated.bundle`
//!     (used for every Required-policy Rotate scenario)
//!   * v2 ratification sidecars (Run 167 / Run 168 corpus, also
//!     re-used as the wire-publish-time governance-proof JSON via
//!     `proof.*.json` siblings):
//!     * `ratification.no_proof.ratify.seq1.json`
//!     * `ratification.no_proof.rotate.seq2.json`
//!     * `ratification.valid_proof.rotate.seq2.json`
//!     * `ratification.idempotent.rotate.seq2.json`
//!     * `ratification.malformed_proof.rotate.seq2.json`
//!     * `ratification.wrong_root.rotate.seq2.json`
//!     * `ratification.wrong_action.rotate.seq2.json`
//!     * `ratification.wrong_digest.rotate.seq2.json`
//!     * `ratification.wrong_sequence.rotate.seq2.json`
//!     * `ratification.invalid_signature.rotate.seq2.json`
//!     * `ratification.unsupported_suite.rotate.seq2.json`
//!     * `ratification.onchain_governance.rotate.seq2.json`
//!   * proof-only JSON siblings for the Run 177 wire-publish carrier:
//!     * `proof.valid.json`              - well-formed GenesisBound Rotate proof
//!     * `proof.malformed.json`          - schema_version=0 (Run 167 Malformed)
//!     * `proof.wrong_root.json`         - proof binds to wrong authority root
//!     * `proof.wrong_action.json`       - proof claims wrong lifecycle action
//!     * `proof.wrong_digest.json`       - proof signs wrong candidate digest
//!     * `proof.wrong_sequence.json`     - proof binds to wrong authority-domain sequence
//!     * `proof.invalid_signature.json`  - proof has invalid issuer signature bytes
//!     * `proof.unsupported_suite.json`  - proof issuer suite is unsupported
//!     * `proof.onchain_governance.json` - OnChainGovernance class proof
//!
//! Plus, under `<OUT_DIR>/mainnet/`:
//!
//!   * MainNet equivalents of the above (used to prove the R22 MainNet
//!     peer-driven apply refusal even with Required + valid proof +
//!     valid candidate + wire-attached carrier).
//!
//! Usage:
//! ```text
//! run_177_live_0x05_governance_proof_release_binary_helper <OUTDIR>
//! ```
//!
//! Run 177 lifts the live inbound `0x05` proof-carrying boundary to
//! release-binary evidence on real `target/release/qbind-node` nodes.
//! The Run 176 source/test integration suite already covers the carrier
//! at source level; this helper closes the release-binary side by
//! producing wire-attachable proof JSONs for the publisher's hidden
//! `--p2p-trust-bundle-peer-candidate-wire-publish-governance-proof-path`
//! flag.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use qbind_crypto::MlDsa44Backend;
use qbind_ledger::bundle_signing_ratification::v2_test_helpers;
use qbind_ledger::{
    compute_canonical_genesis_hash, format_genesis_hash, BundleSigningRatificationV2,
    BundleSigningRatificationV2Action, GenesisAllocation, GenesisAuthorityConfig,
    GenesisAuthorityRoot, GenesisConfig, GenesisCouncilConfig, GenesisHash,
    GenesisMonetaryConfig, GenesisValidator, NetworkEnvironmentPolicy, RatificationEnvironment,
    GENESIS_AUTHORITY_SUITE_ML_DSA_44,
};
use qbind_node::pqc_authority_lifecycle::LocalLifecycleAction;
use qbind_node::pqc_authority_state::{
    AuthorityStateUpdateSource, PersistentAuthorityStateRecordV2,
};
use qbind_node::pqc_devnet_helper::mint_devnet_root;
use qbind_node::pqc_governance_authority::{
    fixture_issuer_signature, GovernanceAuthorityClass,
    PQC_GOVERNANCE_ISSUER_SUITE_ML_DSA_44,
};
use qbind_node::pqc_governance_proof_wire::{
    GovernanceAuthorityClassWire, GovernanceAuthorityProofWire,
    GOVERNANCE_AUTHORITY_PROOF_WIRE_SCHEMA_VERSION,
};
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
use qbind_node::pqc_trust_bundle::{
    canonical_fingerprint, derive_signing_key_id, sign_bundle_devnet_helper, BundleSigningKey,
    BundleSigningKeySet, RootStatus, TrustBundle, TrustBundleEnvironment, TrustBundleRoot,
};
use qbind_node::pqc_trust_peer_candidate::PeerCandidateEnvelope;
use qbind_types::NetworkEnvironment;

const FIXED_TS: u64 = 1_738_000_000;

fn hex_lower(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        use std::fmt::Write;
        let _ = write!(&mut s, "{:02x}", x);
    }
    s
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) {
    fs::write(path, serde_json::to_vec_pretty(value).expect("serialize")).expect("write");
}

fn write_bytes(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("write bytes");
}

fn env_policy(env: NetworkEnvironment) -> NetworkEnvironmentPolicy {
    match env {
        NetworkEnvironment::Mainnet => NetworkEnvironmentPolicy::Mainnet,
        NetworkEnvironment::Testnet => NetworkEnvironmentPolicy::Testnet,
        NetworkEnvironment::Devnet => NetworkEnvironmentPolicy::Devnet,
    }
}

fn rat_env(env: NetworkEnvironment) -> RatificationEnvironment {
    match env {
        NetworkEnvironment::Mainnet => RatificationEnvironment::Mainnet,
        NetworkEnvironment::Testnet => RatificationEnvironment::Testnet,
        NetworkEnvironment::Devnet => RatificationEnvironment::Devnet,
    }
}

fn bundle_env(env: NetworkEnvironment) -> TrustBundleEnvironment {
    match env {
        NetworkEnvironment::Mainnet => TrustBundleEnvironment::Mainnet,
        NetworkEnvironment::Testnet => TrustBundleEnvironment::Testnet,
        NetworkEnvironment::Devnet => TrustBundleEnvironment::Devnet,
    }
}

fn genesis_chain_id(env: NetworkEnvironment) -> &'static str {
    match env {
        NetworkEnvironment::Mainnet => "qbind-mainnet-v0",
        NetworkEnvironment::Testnet => "qbind-testnet-v0",
        NetworkEnvironment::Devnet => "qbind-devnet-v0",
    }
}

struct Signing {
    pk: Vec<u8>,
    sk: Vec<u8>,
    key_id: [u8; 32],
    spec: String,
}

fn mint_signing() -> Signing {
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("ML-DSA-44 signing keygen");
    let key_id = derive_signing_key_id(&pk);
    let spec = format!(
        "{}:{}:{}",
        hex_lower(&key_id),
        PQC_TRANSPORT_SUITE_ML_DSA_44,
        hex_lower(&pk)
    );
    Signing { pk, sk, key_id, spec }
}

struct Harness {
    env: NetworkEnvironment,
    chain_id_hex: String,
    genesis: GenesisConfig,
    canonical_hash: GenesisHash,
    canonical_hash_marker_hex: String,
    canonical_hash_text_hex: String,
    authority_pk: Vec<u8>,
    authority_pk_hex: String,
    authority_sk: Vec<u8>,
    root_id_hex: String,
    root_pk_hex: String,
}

fn harness(env: NetworkEnvironment) -> Harness {
    let (authority_pk, authority_sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 authority keygen");
    let authority_pk_hex = hex_lower(&authority_pk);
    let authority_root = GenesisAuthorityRoot::with_public_key_bytes(
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        &authority_pk,
        "run177-bundle-signing-authority",
    );
    let root = mint_devnet_root().expect("mint transport root");
    let chain_id = env.chain_id();
    let chain_id_hex_str = qbind_node::pqc_trust_sequence::chain_id_hex(chain_id);
    let mut genesis = GenesisConfig::new(
        genesis_chain_id(env),
        1_738_000_000_000,
        vec![GenesisAllocation::new(format!("0x{}", "11".repeat(32)), 100)],
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
    genesis.authority = Some(GenesisAuthorityConfig::new(vec![authority_root]));
    let canonical_hash = compute_canonical_genesis_hash(&genesis, env_policy(env));
    let canonical_hash_text_hex = format_genesis_hash(&canonical_hash);
    let canonical_hash_marker_hex = hex_lower(&canonical_hash);
    Harness {
        env,
        chain_id_hex: chain_id_hex_str,
        genesis,
        canonical_hash,
        canonical_hash_marker_hex,
        canonical_hash_text_hex,
        authority_pk,
        authority_pk_hex,
        authority_sk,
        root_id_hex: hex_lower(&root.root_key_id),
        root_pk_hex: hex_lower(&root.root_pk),
    }
}

fn signed_bundle(h: &Harness, signing: &Signing, sequence: u64) -> TrustBundle {
    let signing_keys = BundleSigningKeySet::from_keys_unchecked(vec![BundleSigningKey {
        key_id_bytes: signing.key_id,
        suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
        pk_bytes: signing.pk.clone(),
    }]);
    assert!(!signing_keys.is_empty());
    let mut bundle = TrustBundle {
        bundle_version: TrustBundle::SUPPORTED_SCHEMA_VERSION,
        environment: bundle_env(h.env),
        chain_id: Some(h.chain_id_hex.clone()),
        generated_at: 10,
        valid_from: 0,
        valid_until: u64::MAX,
        sequence,
        roots: vec![TrustBundleRoot {
            root_id: h.root_id_hex.clone(),
            suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
            root_pk: h.root_pk_hex.clone(),
            status: RootStatus::Active,
            not_before: 0,
            not_after: u64::MAX,
            activation_epoch: None,
            activation_height: None,
        }],
        revocations: vec![],
        signature: None,
        activation_epoch: None,
        activation_height: None,
    };
    let sig = sign_bundle_devnet_helper(&bundle, signing.key_id, &signing.sk).expect("sign bundle");
    bundle.signature = Some(sig);
    bundle
}

fn envelope_for(h: &Harness, bundle: &TrustBundle, peer_id: &str) -> PeerCandidateEnvelope {
    let fp = hex_lower(&canonical_fingerprint(bundle));
    let bytes = serde_json::to_vec_pretty(bundle).expect("serialize bundle");
    PeerCandidateEnvelope {
        envelope_version: PeerCandidateEnvelope::ENVELOPE_VERSION,
        domain_tag: PeerCandidateEnvelope::DOMAIN_TAG.to_string(),
        peer_id: Some(peer_id.to_string()),
        environment: bundle_env(h.env),
        chain_id_hex: h.chain_id_hex.clone(),
        declared_sequence: bundle.sequence,
        declared_fingerprint_prefix: fp[..8].to_string(),
        declared_length: bytes.len(),
        bundle_bytes: bytes,
    }
}

fn build_v2_ratify_seq1(h: &Harness, target: &Signing) -> BundleSigningRatificationV2 {
    v2_test_helpers::build_signed_ratification_v2(
        &h.chain_id_hex,
        rat_env(h.env),
        h.canonical_hash,
        1,
        &h.authority_pk_hex,
        &h.authority_sk,
        &target.pk,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        None,
        None,
        None,
        None,
        None,
    )
}

fn build_v2_rotate_seq2(
    h: &Harness,
    new_target: &Signing,
    previous: &Signing,
    previous_v2_digest_hex: String,
) -> BundleSigningRatificationV2 {
    v2_test_helpers::build_signed_ratification_v2(
        &h.chain_id_hex,
        rat_env(h.env),
        h.canonical_hash,
        1,
        &h.authority_pk_hex,
        &h.authority_sk,
        &new_target.pk,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(qbind_ledger::pqc_public_key_fingerprint(&previous.pk)),
        Some(previous_v2_digest_hex),
        None,
        None,
        None,
        None,
    )
}

fn v2_digest_hex(v: &BundleSigningRatificationV2) -> String {
    hex_lower(&qbind_ledger::canonical_ratification_v2_digest(v))
}

fn good_genesis_rotate_proof_wire(
    h: &Harness,
    rotate: &BundleSigningRatificationV2,
    active_pk: &[u8],
    previous_pk: &[u8],
) -> GovernanceAuthorityProofWire {
    let candidate_digest = v2_digest_hex(rotate);
    let signature = fixture_issuer_signature(
        GovernanceAuthorityClass::GenesisBound,
        &h.authority_pk_hex,
        &candidate_digest,
        rotate.authority_domain_sequence,
    );
    GovernanceAuthorityProofWire {
        schema_version: GOVERNANCE_AUTHORITY_PROOF_WIRE_SCHEMA_VERSION,
        environment: bundle_env(h.env),
        chain_id: h.chain_id_hex.clone(),
        genesis_hash: h.canonical_hash_marker_hex.clone(),
        authority_root_fingerprint: h.authority_pk_hex.clone(),
        authority_root_suite_id: GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        lifecycle_action: LocalLifecycleAction::Rotate,
        active_bundle_signing_key_fingerprint: qbind_ledger::pqc_public_key_fingerprint(active_pk),
        new_bundle_signing_key_fingerprint: Some(qbind_ledger::pqc_public_key_fingerprint(
            active_pk,
        )),
        revoked_bundle_signing_key_fingerprint: Some(qbind_ledger::pqc_public_key_fingerprint(
            previous_pk,
        )),
        authority_domain_sequence: rotate.authority_domain_sequence,
        candidate_v2_digest: candidate_digest,
        issuer_authority_class: GovernanceAuthorityClassWire::GenesisBound,
        issuer_signature_suite_id: PQC_GOVERNANCE_ISSUER_SUITE_ML_DSA_44,
        issuer_signature: signature,
        threshold: None,
    }
}

fn build_sidecar_json(
    rat: &BundleSigningRatificationV2,
    proof_sibling: Option<&GovernanceAuthorityProofWire>,
) -> Vec<u8> {
    let mut value = serde_json::to_value(rat).expect("v2 serialise");
    if let Some(wire) = proof_sibling {
        value["governance_authority_proof"] =
            serde_json::to_value(wire).expect("wire serialise");
    }
    serde_json::to_vec_pretty(&value).expect("sidecar serialise")
}

fn build_sidecar_json_raw_sibling(
    rat: &BundleSigningRatificationV2,
    raw: serde_json::Value,
) -> Vec<u8> {
    let mut value = serde_json::to_value(rat).expect("v2 serialise");
    value["governance_authority_proof"] = raw;
    serde_json::to_vec_pretty(&value).expect("sidecar serialise")
}

fn write_env_fixtures(base: &Path, env: NetworkEnvironment) {
    fs::create_dir_all(base).expect("mkdir env outdir");
    let h = harness(env);
    let active = mint_signing();
    let rotated = mint_signing();

    write_json(&base.join("genesis.json"), &h.genesis);
    fs::write(
        base.join("expected-genesis-hash.txt"),
        format!("{}\n", &h.canonical_hash_text_hex),
    )
    .expect("write expected hash");
    fs::write(
        base.join("signing-key.ratified.spec"),
        format!("{}\n", active.spec),
    )
    .expect("write ratified spec");

    let baseline_bundle = signed_bundle(&h, &active, 1);
    let candidate_bundle = signed_bundle(&h, &active, 2);
    let candidate_rotated_bundle = signed_bundle(&h, &rotated, 2);
    write_bytes(
        &base.join("baseline.bundle"),
        &serde_json::to_vec_pretty(&baseline_bundle).expect("ser baseline"),
    );
    write_bytes(
        &base.join("candidate.bundle"),
        &serde_json::to_vec_pretty(&candidate_bundle).expect("ser candidate"),
    );
    write_bytes(
        &base.join("candidate.rotated.bundle"),
        &serde_json::to_vec_pretty(&candidate_rotated_bundle).expect("ser candidate.rotated"),
    );
    let rotated_key_id = derive_signing_key_id(&rotated.pk);
    let rotated_spec = format!(
        "{}:{}:{}",
        hex_lower(&rotated_key_id),
        PQC_TRANSPORT_SUITE_ML_DSA_44,
        hex_lower(&rotated.pk)
    );
    fs::write(
        base.join("signing-key.rotated.spec"),
        format!("{}\n", rotated_spec),
    )
    .expect("write rotated spec");

    write_json(
        &base.join("peer-candidate.candidate.json"),
        &envelope_for(&h, &candidate_bundle, "run177-active"),
    );
    write_json(
        &base.join("peer-candidate.rotated.json"),
        &envelope_for(&h, &candidate_rotated_bundle, "run177-rotated"),
    );

    let v2_ratify_seq1 = build_v2_ratify_seq1(&h, &active);
    let v2_ratify_seq1_digest_hex = v2_digest_hex(&v2_ratify_seq1);
    write_json(
        &base.join("ratification.no_proof.ratify.seq1.json"),
        &v2_ratify_seq1,
    );

    let v2_marker_seq1 = PersistentAuthorityStateRecordV2::new(
        h.chain_id_hex.clone(),
        bundle_env(env),
        h.canonical_hash_marker_hex.clone(),
        h.authority_pk_hex.clone(),
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        qbind_ledger::pqc_public_key_fingerprint(&active.pk),
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        v2_ratify_seq1_digest_hex.clone(),
        None,
        AuthorityStateUpdateSource::TestOrFixture,
        FIXED_TS,
    );
    write_json(&base.join("seed-marker.v2.seq1.json"), &v2_marker_seq1);

    let v2_rotate_seq2 =
        build_v2_rotate_seq2(&h, &rotated, &active, v2_ratify_seq1_digest_hex.clone());
    let v2_rotate_seq2_digest_hex = v2_digest_hex(&v2_rotate_seq2);

    // No-proof Rotate sidecar (also the receiver's --p2p-trust-bundle-ratification
    // for R1 / R2 / no-proof scenarios under Required policy).
    write_bytes(
        &base.join("ratification.no_proof.rotate.seq2.json"),
        &build_sidecar_json(&v2_rotate_seq2, None),
    );

    // Valid GenesisBound Rotate proof (Run 167 schema).
    let good_proof =
        good_genesis_rotate_proof_wire(&h, &v2_rotate_seq2, &rotated.pk, &active.pk);
    write_bytes(
        &base.join("ratification.valid_proof.rotate.seq2.json"),
        &build_sidecar_json(&v2_rotate_seq2, Some(&good_proof)),
    );
    write_bytes(
        &base.join("ratification.idempotent.rotate.seq2.json"),
        &build_sidecar_json(&v2_rotate_seq2, Some(&good_proof)),
    );

    // Run 177 — proof-only JSON siblings consumed by the binary's
    // hidden harness-only `--p2p-trust-bundle-peer-candidate-wire-publish-
    // governance-proof-path` flag. The publisher attaches the parsed
    // `GovernanceAuthorityProofWire` to the live `0x05` wire envelope's
    // additive Run 176 `governance_authority_proof` field before
    // encoding. Receiver-side gating reaches the Run 165 governance gate
    // through the Run 176 → Run 173 → Run 169 → Run 165 chain.
    write_json(&base.join("proof.valid.json"), &good_proof);

    let malformed_proof_value = serde_json::json!({
        "schema_version": 0,
        "environment": match env {
            NetworkEnvironment::Mainnet => "Mainnet",
            NetworkEnvironment::Testnet => "Testnet",
            NetworkEnvironment::Devnet => "Devnet",
        },
        "chain_id": h.chain_id_hex,
        "genesis_hash": h.canonical_hash_marker_hex,
        "authority_root_fingerprint": h.authority_pk_hex,
        "authority_root_suite_id": GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        "lifecycle_action": "Rotate",
        "active_bundle_signing_key_fingerprint":
            qbind_ledger::pqc_public_key_fingerprint(&rotated.pk),
        "authority_domain_sequence": 2u64,
        "candidate_v2_digest": v2_rotate_seq2_digest_hex,
        "issuer_authority_class": "genesis-bound",
        "issuer_signature_suite_id": PQC_GOVERNANCE_ISSUER_SUITE_ML_DSA_44,
        "issuer_signature": "00",
    });
    write_bytes(
        &base.join("proof.malformed.json"),
        &serde_json::to_vec_pretty(&malformed_proof_value).expect("malformed proof serialise"),
    );
    write_bytes(
        &base.join("ratification.malformed_proof.rotate.seq2.json"),
        &build_sidecar_json_raw_sibling(&v2_rotate_seq2, malformed_proof_value),
    );

    let mut wrong_root = good_proof.clone();
    wrong_root.authority_root_fingerprint = "00".repeat(32);
    write_json(&base.join("proof.wrong_root.json"), &wrong_root);
    write_bytes(
        &base.join("ratification.wrong_root.rotate.seq2.json"),
        &build_sidecar_json(&v2_rotate_seq2, Some(&wrong_root)),
    );

    let mut wrong_action = good_proof.clone();
    wrong_action.lifecycle_action = LocalLifecycleAction::ActivateInitial;
    wrong_action.revoked_bundle_signing_key_fingerprint = None;
    write_json(&base.join("proof.wrong_action.json"), &wrong_action);
    write_bytes(
        &base.join("ratification.wrong_action.rotate.seq2.json"),
        &build_sidecar_json(&v2_rotate_seq2, Some(&wrong_action)),
    );

    let mut wrong_digest = good_proof.clone();
    wrong_digest.candidate_v2_digest = "00".repeat(32);
    write_json(&base.join("proof.wrong_digest.json"), &wrong_digest);
    write_bytes(
        &base.join("ratification.wrong_digest.rotate.seq2.json"),
        &build_sidecar_json(&v2_rotate_seq2, Some(&wrong_digest)),
    );

    let mut wrong_seq = good_proof.clone();
    wrong_seq.authority_domain_sequence = 99;
    write_json(&base.join("proof.wrong_sequence.json"), &wrong_seq);
    write_bytes(
        &base.join("ratification.wrong_sequence.rotate.seq2.json"),
        &build_sidecar_json(&v2_rotate_seq2, Some(&wrong_seq)),
    );

    let mut invalid_sig = good_proof.clone();
    invalid_sig.issuer_signature = vec![0xab; 32];
    write_json(&base.join("proof.invalid_signature.json"), &invalid_sig);
    write_bytes(
        &base.join("ratification.invalid_signature.rotate.seq2.json"),
        &build_sidecar_json(&v2_rotate_seq2, Some(&invalid_sig)),
    );

    let mut unsupported_suite = good_proof.clone();
    unsupported_suite.issuer_signature_suite_id = 1;
    write_json(
        &base.join("proof.unsupported_suite.json"),
        &unsupported_suite,
    );
    write_bytes(
        &base.join("ratification.unsupported_suite.rotate.seq2.json"),
        &build_sidecar_json(&v2_rotate_seq2, Some(&unsupported_suite)),
    );

    let mut onchain = good_proof.clone();
    onchain.issuer_authority_class = GovernanceAuthorityClassWire::OnChainGovernance;
    write_json(&base.join("proof.onchain_governance.json"), &onchain);
    write_bytes(
        &base.join("ratification.onchain_governance.rotate.seq2.json"),
        &build_sidecar_json(&v2_rotate_seq2, Some(&onchain)),
    );

    drop(h.authority_sk);
    drop(active.sk);
    drop(rotated.sk);
    let _ = h.authority_pk;
    let _ = h.canonical_hash;
    let _ = v2_rotate_seq2_digest_hex;
}

fn main() {
    let outdir = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .expect(
            "usage: run_177_live_0x05_governance_proof_release_binary_helper <OUTDIR>",
        );
    let _ = fs::remove_dir_all(&outdir);
    fs::create_dir_all(&outdir).expect("mkdir outdir");

    write_env_fixtures(&outdir.join("devnet"), NetworkEnvironment::Devnet);
    write_env_fixtures(&outdir.join("mainnet"), NetworkEnvironment::Mainnet);

    eprintln!(
        "[run-177] release-built live `0x05` governance-proof carrier fixtures written under {}",
        outdir.display()
    );
}