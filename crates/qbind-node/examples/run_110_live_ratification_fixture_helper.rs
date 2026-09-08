//! Run 110 evidence-only fixture helper.
//!
//! Overlays Run 100/101/103/104 genesis-authority + bundle-signing-key
//! ratification artifacts on top of an existing DevNet trust-material
//! directory produced by `devnet_pqc_trust_bundle_helper`. The output is
//! consumed by the `scripts/devnet/run_110_live_peer_candidate_ratification_n3.sh`
//! multi-node release-binary harness, which exercises the Run 109 live
//! `0x05` peer-candidate wire ratification gate.
//!
//! This helper is an example target only. It does not run in production,
//! does not introduce static source-code anchors, does not introduce
//! fallback authorities, does not change any wire format, and does not
//! create any apply path. It only writes JSON fixture files.
//!
//! Layout produced under `<outdir>/`:
//!
//! ```text
//! genesis.json                       (Run 101 GenesisConfig with authority block)
//! expected-genesis-hash.txt          (Run 102 canonical genesis hash)
//! ratification.valid.json            (Run 103 sidecar covering the
//!                                     existing DevNet trust-bundle's
//!                                     signing key — the "ratified" key)
//! ratification.bad-signature.json    (same payload, signature byte 0 flipped)
//! signing-key.unratified.spec        (a freshly-minted ML-DSA-44 spec line
//!                                     NOT covered by ratification.valid.json —
//!                                     V1 accepts it via --p2p-trust-bundle-signing-key
//!                                     so the U1-signed candidate bundle
//!                                     signature-validates locally, BUT the
//!                                     Run 109 ratification gate rejects it
//!                                     with `RatificationRefused(Missing)`)
//! signing-key.ratified.spec          (a verbatim copy of the existing
//!                                     `<material>/signing-key.spec` for
//!                                     scripting convenience)
//! unratified-bundle.json             (alternate signed TrustBundle: same roots
//!                                     as the existing bundle, sequence = existing+1,
//!                                     signed by the unratified U1 key)
//! envelope.ratified.json             (PeerCandidateEnvelope wrapping the
//!                                     existing R1-signed bundle)
//! envelope.unratified.json           (PeerCandidateEnvelope wrapping the
//!                                     U1-signed alternate bundle)
//! summary.json                       (machine-readable record of the
//!                                     fixture identities)
//! ```
//!
//! Usage:
//!
//! ```text
//! run_110_live_ratification_fixture_helper <material-dir> <outdir>
//! ```
//!
//! `<material-dir>` is the path passed to `devnet_pqc_trust_bundle_helper`
//! (it must already contain `trust-bundle.json` and `signing-key.spec`).

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use qbind_crypto::MlDsa44Backend;
use qbind_ledger::bundle_signing_ratification::test_helpers as ratification_helpers;
use qbind_ledger::{
    compute_canonical_genesis_hash, format_genesis_hash, GenesisAllocation, GenesisAuthorityConfig,
    GenesisAuthorityRoot, GenesisConfig, GenesisCouncilConfig, GenesisMonetaryConfig,
    GenesisValidator, NetworkEnvironmentPolicy, RatificationEnvironment,
    GENESIS_AUTHORITY_SUITE_ML_DSA_44,
};
use qbind_node::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
use qbind_node::pqc_trust_bundle::{
    canonical_fingerprint, derive_signing_key_id, sign_bundle_devnet_helper, TrustBundle,
    TrustBundleEnvironment,
};
use qbind_node::pqc_trust_peer_candidate::PeerCandidateEnvelope;

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

fn hex_decode(hex: &str) -> Vec<u8> {
    assert!(
        hex.len() % 2 == 0,
        "hex string has odd length: {}",
        hex.len()
    );
    let mut out = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        out.push(u8::from_str_radix(&hex[i..i + 2], 16).expect("hex parse"));
    }
    out
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) {
    fs::write(
        path,
        serde_json::to_vec_pretty(value).expect("serialize json"),
    )
    .expect("write json");
}

struct ExistingSigningKey {
    key_id_hex: String,
    suite_id: u8,
    pk: Vec<u8>,
}

fn read_existing_signing_key_spec(material_dir: &Path) -> ExistingSigningKey {
    let spec = fs::read_to_string(material_dir.join("signing-key.spec"))
        .expect("read material/signing-key.spec");
    let spec = spec.trim();
    let parts: Vec<&str> = spec.split(':').collect();
    assert_eq!(
        parts.len(),
        3,
        "signing-key.spec must be KEYID:SUITE:PK, got {:?}",
        spec
    );
    let suite_id: u8 = parts[1].parse().expect("parse suite id");
    assert_eq!(
        suite_id, PQC_TRANSPORT_SUITE_ML_DSA_44,
        "Run 110 helper only supports ML-DSA-44 signing keys"
    );
    ExistingSigningKey {
        key_id_hex: parts[0].to_string(),
        suite_id,
        pk: hex_decode(parts[2]),
    }
}

fn devnet_chain_id_str() -> String {
    // Matches `qbind_node::pqc_trust_sequence::chain_id_hex(NetworkEnvironment::Devnet.chain_id())`
    // for the DevNet environment used by Run 089-style harness baselines.
    use qbind_node::pqc_trust_sequence::chain_id_hex;
    use qbind_types::NetworkEnvironment;
    chain_id_hex(NetworkEnvironment::Devnet.chain_id())
}

fn mint_genesis_with_authority(authority_pk: &[u8]) -> (GenesisConfig, qbind_ledger::GenesisHash) {
    let authority_root = GenesisAuthorityRoot::with_public_key_bytes(
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        authority_pk,
        "run110-bundle-signing-authority",
    );
    let mut genesis = GenesisConfig::new(
        "qbind-devnet-v0",
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
    genesis.authority = Some(GenesisAuthorityConfig::new(vec![authority_root]));
    let canonical_hash = compute_canonical_genesis_hash(&genesis, NetworkEnvironmentPolicy::Devnet);
    (genesis, canonical_hash)
}

fn build_envelope(bundle: &TrustBundle, peer_id: &str) -> PeerCandidateEnvelope {
    let bytes = serde_json::to_vec_pretty(bundle).expect("serialize bundle");
    let fp = hex_lower(&canonical_fingerprint(bundle));
    PeerCandidateEnvelope {
        envelope_version: PeerCandidateEnvelope::ENVELOPE_VERSION,
        domain_tag: PeerCandidateEnvelope::DOMAIN_TAG.to_string(),
        peer_id: Some(peer_id.to_string()),
        environment: TrustBundleEnvironment::Devnet,
        chain_id_hex: devnet_chain_id_str(),
        declared_sequence: bundle.sequence,
        declared_fingerprint_prefix: fp[..8].to_string(),
        declared_length: bytes.len(),
        bundle_bytes: bytes,
    }
}

fn main() {
    let mut args = env::args_os();
    let _bin = args.next();
    let material_dir = args
        .next()
        .map(PathBuf::from)
        .expect("usage: run_110_live_ratification_fixture_helper <material-dir> <outdir>");
    let outdir = args
        .next()
        .map(PathBuf::from)
        .expect("usage: run_110_live_ratification_fixture_helper <material-dir> <outdir>");

    fs::create_dir_all(&outdir).expect("mkdir outdir");

    // --- Load existing R1 signing key (the ratified key the cluster's
    // baseline trust bundle is signed with) ----------------------------------
    let r1 = read_existing_signing_key_spec(&material_dir);

    // --- Mint genesis + authority -------------------------------------------
    let (authority_pk, authority_sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 authority keygen");
    let (genesis, canonical_hash) = mint_genesis_with_authority(&authority_pk);
    let authority_fp = hex_lower(&authority_pk);
    let chain_id_str = devnet_chain_id_str();

    write_json(&outdir.join("genesis.json"), &genesis);
    fs::write(
        outdir.join("expected-genesis-hash.txt"),
        format!("{}\n", format_genesis_hash(&canonical_hash)),
    )
    .expect("write expected hash");

    // --- Build the VALID ratification covering R1 ---------------------------
    let valid_ratification = ratification_helpers::build_signed_ratification(
        &chain_id_str,
        RatificationEnvironment::Devnet,
        canonical_hash,
        &authority_fp,
        &authority_sk,
        &r1.pk,
    );

    // --- Tampered ratification (signature byte 0 flipped) -------------------
    let mut bad_ratification = valid_ratification.clone();
    if !bad_ratification.signature.is_empty() {
        bad_ratification.signature[0] ^= 0xff;
    }

    write_json(&outdir.join("ratification.valid.json"), &valid_ratification);
    write_json(
        &outdir.join("ratification.bad-signature.json"),
        &bad_ratification,
    );

    // --- Mint U1 (unratified signing key) -----------------------------------
    let (u1_pk, u1_sk) = MlDsa44Backend::generate_keypair().expect("ML-DSA-44 unratified keygen");
    let u1_key_id = derive_signing_key_id(&u1_pk);
    let u1_spec = format!(
        "{}:{}:{}",
        hex_lower(&u1_key_id),
        PQC_TRANSPORT_SUITE_ML_DSA_44,
        hex_lower(&u1_pk),
    );
    fs::write(
        outdir.join("signing-key.unratified.spec"),
        format!("{}\n", u1_spec),
    )
    .expect("write unratified signing spec");
    fs::write(
        outdir.join("signing-key.ratified.spec"),
        format!("{}:{}:{}\n", r1.key_id_hex, r1.suite_id, hex_lower(&r1.pk)),
    )
    .expect("write ratified signing spec");

    // --- Load existing signed trust bundle (signed by R1) -------------------
    let existing_bundle_bytes =
        fs::read(material_dir.join("trust-bundle.json")).expect("read material/trust-bundle.json");
    let existing_bundle: TrustBundle =
        serde_json::from_slice(&existing_bundle_bytes).expect("parse trust-bundle.json");

    // --- Build the U1-signed alternate bundle (same roots, sequence + 1) ----
    let mut alt_bundle = existing_bundle.clone();
    alt_bundle.sequence = existing_bundle.sequence.saturating_add(1);
    alt_bundle.generated_at = existing_bundle.generated_at.saturating_add(1);
    alt_bundle.signature = None;
    let alt_sig = sign_bundle_devnet_helper(&alt_bundle, u1_key_id, &u1_sk)
        .expect("sign U1 alternate bundle");
    alt_bundle.signature = Some(alt_sig);

    write_json(&outdir.join("unratified-bundle.json"), &alt_bundle);

    // --- Build envelopes ----------------------------------------------------
    let env_ratified = build_envelope(&existing_bundle, "run110-ratified");
    let env_unratified = build_envelope(&alt_bundle, "run110-unratified");
    write_json(&outdir.join("envelope.ratified.json"), &env_ratified);
    write_json(&outdir.join("envelope.unratified.json"), &env_unratified);

    // --- Machine-readable summary ------------------------------------------
    let summary = serde_json::json!({
        "fixture_kind": "run_110_live_ratification",
        "chain_id_hex": chain_id_str,
        "authority_pk_hex": authority_fp,
        "genesis_hash_hex": format_genesis_hash(&canonical_hash),
        "ratified_signing_key_id_hex": r1.key_id_hex,
        "ratified_signing_key_pk_hex": hex_lower(&r1.pk),
        "unratified_signing_key_id_hex": hex_lower(&u1_key_id),
        "unratified_signing_key_pk_hex": hex_lower(&u1_pk),
        "ratified_bundle_sequence": existing_bundle.sequence,
        "unratified_bundle_sequence": alt_bundle.sequence,
        "ratified_envelope_path": "envelope.ratified.json",
        "unratified_envelope_path": "envelope.unratified.json",
        "ratification_valid_path": "ratification.valid.json",
        "ratification_bad_signature_path": "ratification.bad-signature.json",
        "genesis_path": "genesis.json",
        "expected_genesis_hash_path": "expected-genesis-hash.txt",
        "ratified_signing_key_spec_path": "signing-key.ratified.spec",
        "unratified_signing_key_spec_path": "signing-key.unratified.spec",
    });
    fs::write(
        outdir.join("summary.json"),
        serde_json::to_vec_pretty(&summary).expect("serialize summary"),
    )
    .expect("write summary.json");

    eprintln!(
        "[run110-fixture-helper] wrote Run 110 ratification overlay fixtures under {}",
        outdir.display()
    );
}
