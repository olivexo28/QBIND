//! Run 168 — release-built helper exercising the **Run 167 governance-
//! proof carrier** end-to-end through the production sidecar loader
//! (`pqc_ratification_input::load_v2_ratification_sidecar_with_governance_proof_from_path`)
//! and the **Run 165 governance gate**
//! (`pqc_authority_marker_acceptance::decide_v2_marker_acceptance_with_lifecycle_and_governance`).
//!
//! This helper extends the Run 166 helper pattern — release-built binary
//! linking the same production helper symbols
//! (`decide_v2_marker_acceptance_with_lifecycle_and_governance`,
//! `evaluate_governance_marker_gate`,
//! `MutatingSurfaceMarkerV2Error`, plus the Run 167 sidecar loader) —
//! and is therefore honest release-binary evidence that the production
//! marker-decision surfaces parse and enforce proof-carrying v2
//! ratification sidecars per the Run 168 task scope.
//!
//! Per `task/RUN_168_TASK.txt`, this helper exercises:
//!
//!   * **A1** (no-proof sidecar, `NotRequired`)            → accept;
//!   * **A2-equivalent** (no-proof sidecar, `Required`,
//!     ActivateInitial governance-optional)                → accept;
//!   * **A3** (proof-carrying GenesisBound Rotate sidecar,
//!     `Required`)                                         → accept;
//!   * **A7** (idempotent re-presentation of the same proof-
//!     carrying sidecar)                                   → accept-idempotent;
//!   * **R1** (no-proof sidecar, `Required`, Rotate)       → `GovernanceAuthorityRequiredButMissing`;
//!   * **R2** (malformed `governance_authority_proof`
//!     sibling, `Required`, Rotate)                        → `GovernanceAuthorityRequiredButMissing`
//!     (the Run 167 loader maps `Malformed` to
//!     `Unavailable`, fail-closing under `Required`);
//!   * **R5** (wrong authority root)                       → `WrongAuthorityRoot`;
//!   * **R7** (wrong lifecycle action)                     → `WrongLifecycleAction`;
//!   * **R8** (wrong candidate digest)                     → `WrongCandidateDigest`;
//!   * **R9** (wrong authority-domain sequence)            → `WrongAuthoritySequence`;
//!   * **R10** (invalid issuer signature)                  → `InvalidIssuerSignature`;
//!   * **R15** (`OnChainGovernance` proof)                 → `UnsupportedOnChainGovernance`;
//!   * **R16** (local operator config alone — empty
//!     issuer signature)                                   → wire-boundary
//!     `EmptyIssuerSignature` parse error
//!     (`Malformed` ⇒ `Unavailable` ⇒ fail-closed under `Required`).
//!
//! Other Run 168 R-class items (R3 environment, R4 chain, R6 genesis,
//! R11 unsupported issuer suite, R12 non-PQC suite, R13 threshold,
//! R14 stale-replay, R17 peer-majority, R18 lifecycle invalid +
//! governance valid, R19 lifecycle valid + governance invalid) are
//! covered structurally by the Run 167 source/test matrix
//! (`crates/qbind-node/tests/run_167_governance_proof_carrier_tests.rs`)
//! and the Run 163 governance verifier tests
//! (`crates/qbind-node/tests/run_163_governance_authority_verifier_tests.rs`).
//! The Run 168 evidence report (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_168.md`)
//! explicitly cites those tests for completeness.
//!
//! R20 (MainNet peer-driven apply remains refused even with a valid
//! governance proof) is asserted at the harness level
//! (`scripts/devnet/run_168_governance_proof_carrier_release_binary.sh`)
//! by invoking real `target/release/qbind-node` against a MainNet
//! candidate sidecar — that environment refusal is unchanged by Run 165
//! and Run 167 and is owned by the surface (not the gate).
//!
//! Run 168 is release-binary EVIDENCE / ENFORCEMENT only. This helper:
//!   * does NOT enable MainNet peer-driven apply on any surface;
//!   * does NOT mutate any live trust state;
//!   * does NOT open a P2P socket;
//!   * does NOT change any wire / marker / sequence / trust-bundle
//!     schema beyond the additive Run 167 sibling field already landed;
//!   * persists at most an ephemeral seed v2 marker under `<OUT_DIR>/`
//!     for scenarios that need a persisted prior generation, and only
//!     ever via the existing
//!     `persist_accepted_v2_marker_after_commit_boundary` helper after a
//!     `decide_v2_marker_acceptance_with_lifecycle_and_governance`
//!     accept;
//!   * writes proof-carrying sidecar JSON files only under `<OUT_DIR>/`
//!     and reads them back via the **production** Run 167 sidecar
//!     loader (`load_v2_ratification_sidecar_with_governance_proof_from_path`)
//!     so the parse path exercised here is identical to the production
//!     parse path that any future surface wiring will use.
//!
//! Usage:
//! ```text
//! run_168_governance_proof_carrier_release_binary_helper <OUT_DIR>
//! ```
//!
//! Writes:
//! ```text
//! <OUT_DIR>/manifest.txt              # one line per scenario: <id>\t<expected_label>\t<expected_match>
//! <OUT_DIR>/expected_outcomes.txt     # human-readable map
//! <OUT_DIR>/actual_outcomes.txt       # actual typed-outcome Debug dumps
//! <OUT_DIR>/scenarios/<id>/policy.txt
//! <OUT_DIR>/scenarios/<id>/load_status.txt    # GovernanceProofLoadStatus variant
//! <OUT_DIR>/scenarios/<id>/expected.txt
//! <OUT_DIR>/scenarios/<id>/actual.txt
//! <OUT_DIR>/scenarios/<id>/sidecar.json       # the proof-carrying sidecar parsed
//! <OUT_DIR>/scenarios/<id>/sidecar.sha256     # SHA-256 of sidecar.json
//! <OUT_DIR>/scenarios/<id>/marker_pre.sha256  # if the scenario seeded a marker
//! <OUT_DIR>/scenarios/<id>/marker_post.sha256 # always — proves no mutation on rejection
//! <OUT_DIR>/scenarios/<id>/marker_path.txt
//! ```

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use qbind_crypto::MlDsa44Backend;
use qbind_ledger::{
    bundle_signing_ratification::v2_test_helpers as ratification_v2_helpers,
    compute_canonical_genesis_hash, BundleSigningRatificationV2,
    BundleSigningRatificationV2Action, GenesisAllocation, GenesisAuthorityConfig,
    GenesisAuthorityRoot, GenesisConfig, GenesisCouncilConfig, GenesisHash,
    GenesisMonetaryConfig, GenesisValidator, NetworkEnvironmentPolicy, RatificationEnvironment,
    GENESIS_AUTHORITY_SUITE_ML_DSA_44,
};
use qbind_node::pqc_authority_lifecycle::LocalLifecycleAction;
use qbind_node::pqc_authority_marker_acceptance::{
    decide_v2_marker_acceptance_with_lifecycle_and_governance,
    persist_accepted_v2_marker_after_commit_boundary, MarkerAcceptDecisionV2,
    MarkerAcceptKindV2, MarkerAcceptanceV2Inputs, MutatingSurfaceMarkerV2Error,
};
use qbind_node::pqc_authority_state::{
    authority_state_file_path, AuthorityStateUpdateSource, PersistentAuthorityStateRecordV2,
};
use qbind_node::pqc_governance_authority::{
    fixture_issuer_signature, fixture_issuer_signature_verifier, GovernanceAuthorityClass,
    GovernanceAuthorityProof, GovernanceAuthorityVerificationOutcome, GovernanceProofContext,
    GovernanceProofPolicy, PQC_GOVERNANCE_ISSUER_SUITE_ML_DSA_44,
};
use qbind_node::pqc_governance_proof_wire::{
    GovernanceAuthorityProofWire, GovernanceProofLoadStatus,
};
use qbind_node::pqc_ratification_input::load_v2_ratification_sidecar_with_governance_proof_from_path;
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;
use qbind_node::pqc_trust_sequence::chain_id_hex;
use qbind_types::NetworkEnvironment;

const FIXED_TS: u64 = 1_700_000_000;

fn hex_lower(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", x);
    }
    s
}

fn write_text(path: &Path, body: &str) {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p).expect("create parent dir");
    }
    let mut f = fs::File::create(path).expect("create file");
    f.write_all(body.as_bytes()).expect("write file");
}

fn sha256_hex_of(path: &Path) -> String {
    use sha3::{Digest, Sha3_256};
    let bytes = fs::read(path).expect("read file for sha256");
    let mut h = Sha3_256::new();
    h.update(&bytes);
    hex_lower(&h.finalize())
}

struct Harness {
    authority_pk: Vec<u8>,
    authority_sk: Vec<u8>,
    signing_pk_a: Vec<u8>,
    signing_pk_b: Vec<u8>,
    genesis_cfg: GenesisConfig,
    canonical_hash: GenesisHash,
    chain_id_str: String,
    env_policy: NetworkEnvironmentPolicy,
}

fn devnet_harness() -> Harness {
    let (authority_pk, authority_sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen authority key");
    let (signing_pk_a, _a) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen signing key A");
    let (signing_pk_b, _b) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen signing key B");
    let chain_id = NetworkEnvironment::Devnet.chain_id();
    let chain_id_str = chain_id_hex(chain_id);
    let mut genesis_cfg = GenesisConfig::new(
        &chain_id_str,
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
    let auth_root = GenesisAuthorityRoot::new(
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        &hex_lower(&authority_pk),
        "test-bundle-signing-1",
    );
    genesis_cfg.authority = Some(GenesisAuthorityConfig::new(vec![auth_root]));
    let env_policy = NetworkEnvironmentPolicy::Devnet;
    let canonical_hash = compute_canonical_genesis_hash(&genesis_cfg, env_policy);
    Harness {
        authority_pk,
        authority_sk,
        signing_pk_a,
        signing_pk_b,
        genesis_cfg,
        canonical_hash,
        chain_id_str,
        env_policy,
    }
}

impl Harness {
    fn build_v2(
        &self,
        target_pk: &[u8],
        seq: u64,
        action: BundleSigningRatificationV2Action,
        previous_fp: Option<String>,
    ) -> BundleSigningRatificationV2 {
        let policy_version = self
            .genesis_cfg
            .authority
            .as_ref()
            .unwrap()
            .authority_policy_version;
        let previous_digest = matches!(action, BundleSigningRatificationV2Action::Rotate)
            .then(|| "ab".repeat(32));
        ratification_v2_helpers::build_signed_ratification_v2(
            &self.chain_id_str,
            RatificationEnvironment::Devnet,
            self.canonical_hash,
            policy_version,
            &hex_lower(&self.authority_pk),
            &self.authority_sk,
            target_pk,
            seq,
            action,
            previous_fp,
            previous_digest,
            None,
            None,
            None,
            None,
        )
    }

    fn verify_v2(
        &self,
        ratification: &BundleSigningRatificationV2,
    ) -> qbind_ledger::RatifiedBundleSigningKeyV2 {
        qbind_ledger::verify_bundle_signing_key_ratification_v2(
            qbind_ledger::RatificationV2VerifierInputs {
                ratification,
                authority: self.genesis_cfg.authority.as_ref().unwrap(),
                expected_chain_id: &self.chain_id_str,
                expected_environment: self.env_policy,
                expected_genesis_hash: &self.canonical_hash,
            },
        )
        .expect("v2 verifier accepts clean ratification")
    }

    fn genesis_hex(&self) -> String {
        hex_lower(&self.canonical_hash)
    }

    fn root_fp(&self) -> String {
        hex_lower(&self.authority_pk)
    }

    fn derive_candidate(
        &self,
        gh_hex: &str,
        ratification: &BundleSigningRatificationV2,
        ratified: &qbind_ledger::RatifiedBundleSigningKeyV2,
        update_source: AuthorityStateUpdateSource,
    ) -> PersistentAuthorityStateRecordV2 {
        qbind_node::pqc_authority_state::derive_authority_state_v2_from_ratification(
            qbind_node::pqc_authority_state::AuthorityStateDerivationV2Inputs {
                runtime_env: NetworkEnvironment::Devnet,
                runtime_chain_id: NetworkEnvironment::Devnet.chain_id(),
                runtime_genesis_hash_hex: gh_hex,
                ratification,
                ratified,
                update_source,
                updated_at_unix_secs: FIXED_TS,
            },
        )
        .expect("derive v2 candidate")
    }
}

fn make_inputs<'a>(
    marker_path: &'a Path,
    gh_hex: &'a str,
    ratification: &'a BundleSigningRatificationV2,
    ratified: &'a qbind_ledger::RatifiedBundleSigningKeyV2,
    update_source: AuthorityStateUpdateSource,
) -> MarkerAcceptanceV2Inputs<'a> {
    MarkerAcceptanceV2Inputs {
        marker_path,
        runtime_env: NetworkEnvironment::Devnet,
        runtime_chain_id: NetworkEnvironment::Devnet.chain_id(),
        runtime_genesis_hash_hex: gh_hex,
        ratification,
        ratified,
        update_source,
        updated_at_unix_secs: FIXED_TS,
    }
}

/// Build a typed Run 163 [`GovernanceAuthorityProof`] consistent with a
/// candidate / class / lifecycle action triple.
fn good_proof(
    h: &Harness,
    candidate: &PersistentAuthorityStateRecordV2,
    class: GovernanceAuthorityClass,
    action: LocalLifecycleAction,
) -> GovernanceAuthorityProof {
    let root_fp = h.root_fp();
    let new_fp = match action {
        LocalLifecycleAction::ActivateInitial | LocalLifecycleAction::Rotate => {
            Some(candidate.active_bundle_signing_key_fingerprint.clone())
        }
        _ => None,
    };
    let revoked_fp = match action {
        LocalLifecycleAction::Rotate => candidate.previous_bundle_signing_key_fingerprint.clone(),
        _ => None,
    };
    let signature = fixture_issuer_signature(
        class,
        &root_fp,
        &candidate.latest_ratification_v2_digest,
        candidate.latest_authority_domain_sequence,
    );
    GovernanceAuthorityProof {
        environment: TrustBundleEnvironment::Devnet,
        chain_id: h.chain_id_str.clone(),
        genesis_hash: h.genesis_hex(),
        authority_root_fingerprint: root_fp,
        authority_root_suite_id: GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        lifecycle_action: action,
        active_bundle_signing_key_fingerprint: candidate
            .active_bundle_signing_key_fingerprint
            .clone(),
        new_bundle_signing_key_fingerprint: new_fp,
        revoked_bundle_signing_key_fingerprint: revoked_fp,
        authority_domain_sequence: candidate.latest_authority_domain_sequence,
        candidate_v2_digest: candidate.latest_ratification_v2_digest.clone(),
        issuer_authority_class: class,
        issuer_signature_suite_id: PQC_GOVERNANCE_ISSUER_SUITE_ML_DSA_44,
        issuer_signature: signature,
        threshold: None,
    }
}

/// Build a v2 ratification sidecar JSON document and (optionally) splice
/// in an additive `governance_authority_proof` sibling. Returns the
/// rendered JSON bytes ready to write to disk.
fn build_sidecar_json(
    ratification: &BundleSigningRatificationV2,
    proof_sibling: Option<&GovernanceAuthorityProofWire>,
) -> Vec<u8> {
    let mut value = serde_json::to_value(ratification).expect("v2 ratification serialises");
    if let Some(wire) = proof_sibling {
        value["governance_authority_proof"] =
            serde_json::to_value(wire).expect("wire serialises");
    }
    serde_json::to_vec_pretty(&value).expect("serialise sidecar")
}

/// Splice an explicit raw JSON value (e.g. malformed proof) into the v2
/// ratification sidecar at the `governance_authority_proof` field.
fn build_sidecar_json_raw_sibling(
    ratification: &BundleSigningRatificationV2,
    raw: serde_json::Value,
) -> Vec<u8> {
    let mut value = serde_json::to_value(ratification).expect("v2 ratification serialises");
    value["governance_authority_proof"] = raw;
    serde_json::to_vec_pretty(&value).expect("serialise sidecar")
}

/// Encapsulates one scenario record.
struct ScenarioRecord {
    id: &'static str,
    policy: &'static str,
    load_status: String,
    expected_label: &'static str,
    expected_match: &'static str,
    actual: String,
    sidecar_path: PathBuf,
    sidecar_sha: String,
    marker_pre_sha: Option<String>,
    marker_post_sha: Option<String>,
    marker_path: PathBuf,
    expect_no_mutation: bool,
}

fn record_actual<T: std::fmt::Debug, E: std::fmt::Debug>(result: &Result<T, E>) -> String {
    match result {
        Ok(v) => format!("Ok({:?})", v),
        Err(e) => format!("Err({:?})", e),
    }
}

fn load_status_label(s: &GovernanceProofLoadStatus) -> String {
    match s {
        GovernanceProofLoadStatus::Absent => "Absent".to_string(),
        GovernanceProofLoadStatus::Available(_) => "Available".to_string(),
        GovernanceProofLoadStatus::Malformed(e) => format!("Malformed({:?})", e),
    }
}

fn run() -> Vec<ScenarioRecord> {
    let mut out = Vec::new();
    let h = devnet_harness();
    let gh = h.genesis_hex();

    let arg = env::args()
        .nth(1)
        .expect("usage: run_168_governance_proof_carrier_release_binary_helper <OUT_DIR>");
    let out_dir = PathBuf::from(arg);
    fs::create_dir_all(&out_dir).expect("create OUT_DIR");

    // -----------------------------------------------------------------
    // H1 — A1: no-proof sidecar under NotRequired remains accepted.
    //      Sidecar has NO `governance_authority_proof` sibling. The
    //      Run 167 loader returns `Absent`. Gate accepts under
    //      `NotRequired`. No marker write (helper is pre-commit only).
    // -----------------------------------------------------------------
    {
        let id = "H1_a1_absent_not_required_initial_accept";
        let dir = out_dir.join("scenarios").join(id);
        fs::create_dir_all(&dir).expect("h1 dir");
        let sidecar_path = dir.join("sidecar.json");
        let marker_path = authority_state_file_path(&dir);
        let r = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None);
        let bytes = build_sidecar_json(&r, None);
        fs::write(&sidecar_path, &bytes).expect("write sidecar");
        let sidecar_sha = sha256_hex_of(&sidecar_path);
        let loaded = load_v2_ratification_sidecar_with_governance_proof_from_path(&sidecar_path)
            .expect("load no-proof sidecar");
        assert!(matches!(
            loaded.governance_proof,
            GovernanceProofLoadStatus::Absent
        ));
        let load_status = load_status_label(&loaded.governance_proof);
        let ratified = h.verify_v2(&loaded.ratification);
        let result = decide_v2_marker_acceptance_with_lifecycle_and_governance(
            make_inputs(
                &marker_path,
                &gh,
                &loaded.ratification,
                &ratified,
                AuthorityStateUpdateSource::StartupLoad,
            ),
            GovernanceProofPolicy::NotRequired,
            GovernanceProofContext::Unavailable,
        );
        let actual = record_actual(&result);
        if let Ok(d) = &result {
            assert!(matches!(d.kind(), MarkerAcceptKindV2::FirstV2Write));
        } else {
            panic!("H1: expected Ok decision, got {:?}", result);
        }
        let post_sha = if marker_path.exists() {
            Some(sha256_hex_of(&marker_path))
        } else {
            None
        };
        assert!(
            post_sha.is_none(),
            "H1: helper must not write marker before post-commit boundary"
        );
        out.push(ScenarioRecord {
            id,
            policy: "NotRequired",
            load_status,
            expected_label: "Accepted (FirstV2Write); load_status=Absent",
            expected_match: r"Ok\(.*FirstV2Write",
            actual,
            sidecar_path,
            sidecar_sha,
            marker_pre_sha: None,
            marker_post_sha: post_sha,
            marker_path,
            expect_no_mutation: true,
        });
    }

    // -----------------------------------------------------------------
    // H2 — A2-equivalent: no-proof sidecar under
    //      `RequiredForLifecycleSensitive` on `ActivateInitial` remains
    //      accepted because `ActivateInitial` is governance-optional
    //      (Run 165 §A5 chosen-policy semantics). This proves the
    //      `Required` policy does not break first-activation.
    // -----------------------------------------------------------------
    {
        let id = "H2_a2_absent_required_initial_optional";
        let dir = out_dir.join("scenarios").join(id);
        fs::create_dir_all(&dir).expect("h2 dir");
        let sidecar_path = dir.join("sidecar.json");
        let marker_path = authority_state_file_path(&dir);
        let r = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None);
        let bytes = build_sidecar_json(&r, None);
        fs::write(&sidecar_path, &bytes).expect("write sidecar");
        let sidecar_sha = sha256_hex_of(&sidecar_path);
        let loaded = load_v2_ratification_sidecar_with_governance_proof_from_path(&sidecar_path)
            .expect("load no-proof sidecar");
        assert!(matches!(
            loaded.governance_proof,
            GovernanceProofLoadStatus::Absent
        ));
        let load_status = load_status_label(&loaded.governance_proof);
        let ratified = h.verify_v2(&loaded.ratification);
        let verifier = fixture_issuer_signature_verifier();
        let context = loaded.governance_proof.governance_proof_context(&verifier);
        let result = decide_v2_marker_acceptance_with_lifecycle_and_governance(
            make_inputs(
                &marker_path,
                &gh,
                &loaded.ratification,
                &ratified,
                AuthorityStateUpdateSource::StartupLoad,
            ),
            GovernanceProofPolicy::RequiredForLifecycleSensitive,
            context,
        );
        let actual = record_actual(&result);
        if let Ok(d) = &result {
            assert!(matches!(d.kind(), MarkerAcceptKindV2::FirstV2Write));
        } else {
            panic!("H2: expected Ok (ActivateInitial governance-optional), got {:?}", result);
        }
        let post_sha = if marker_path.exists() {
            Some(sha256_hex_of(&marker_path))
        } else {
            None
        };
        assert!(post_sha.is_none(), "H2: helper must not persist");
        out.push(ScenarioRecord {
            id,
            policy: "RequiredForLifecycleSensitive",
            load_status,
            expected_label: "Accepted (FirstV2Write; ActivateInitial governance-optional)",
            expected_match: r"Ok\(.*FirstV2Write",
            actual,
            sidecar_path,
            sidecar_sha,
            marker_pre_sha: None,
            marker_post_sha: post_sha,
            marker_path,
            expect_no_mutation: true,
        });
    }

    // -----------------------------------------------------------------
    // H3 — A3: valid proof-carrying GenesisBound Rotate sidecar accepted
    //      under `RequiredForLifecycleSensitive`. The Run 167 loader
    //      parses the sibling as `Available(GovernanceAuthorityProof)`.
    //      The Run 165 gate accepts. Lifecycle/anti-rollback also pass.
    //      Helper is pre-commit; persisted seed marker bytes remain
    //      byte-for-byte unchanged.
    // -----------------------------------------------------------------
    {
        let id = "H3_a3_available_required_rotate_accept";
        let dir = out_dir.join("scenarios").join(id);
        fs::create_dir_all(&dir).expect("h3 dir");
        let sidecar_path = dir.join("sidecar.json");
        let marker_path = authority_state_file_path(&dir);

        // Seed A at seq 1 via NotRequired accept + post-commit persist.
        let r1 = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None);
        let ratified1 = h.verify_v2(&r1);
        let d1: MarkerAcceptDecisionV2 =
            decide_v2_marker_acceptance_with_lifecycle_and_governance(
                make_inputs(
                    &marker_path,
                    &gh,
                    &r1,
                    &ratified1,
                    AuthorityStateUpdateSource::StartupLoad,
                ),
                GovernanceProofPolicy::NotRequired,
                GovernanceProofContext::Unavailable,
            )
            .expect("h3 seed accept");
        persist_accepted_v2_marker_after_commit_boundary(&d1).expect("h3 persist seed");
        let pre_sha = sha256_hex_of(&marker_path);

        // Build Rotate sidecar with valid GenesisBound proof.
        let r2 = h.build_v2(
            &h.signing_pk_b,
            2,
            BundleSigningRatificationV2Action::Rotate,
            Some(qbind_ledger::pqc_public_key_fingerprint(&h.signing_pk_a)),
        );
        let ratified2 = h.verify_v2(&r2);
        let candidate2 =
            h.derive_candidate(&gh, &r2, &ratified2, AuthorityStateUpdateSource::ReloadApply);
        let proof = good_proof(
            &h,
            &candidate2,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::Rotate,
        );
        let wire = GovernanceAuthorityProofWire::from_governance_authority_proof(&proof);
        let bytes = build_sidecar_json(&r2, Some(&wire));
        fs::write(&sidecar_path, &bytes).expect("write proof-carrying sidecar");
        let sidecar_sha = sha256_hex_of(&sidecar_path);

        // Parse via the Run 167 production loader.
        let loaded = load_v2_ratification_sidecar_with_governance_proof_from_path(&sidecar_path)
            .expect("load proof-carrying sidecar");
        assert!(loaded.governance_proof.is_available(), "H3: must parse Available");
        let load_status = load_status_label(&loaded.governance_proof);

        // Decide via the Run 165 gate.
        let ratified_loaded = h.verify_v2(&loaded.ratification);
        let verifier = fixture_issuer_signature_verifier();
        let context = loaded.governance_proof.governance_proof_context(&verifier);
        let result = decide_v2_marker_acceptance_with_lifecycle_and_governance(
            make_inputs(
                &marker_path,
                &gh,
                &loaded.ratification,
                &ratified_loaded,
                AuthorityStateUpdateSource::ReloadApply,
            ),
            GovernanceProofPolicy::RequiredForLifecycleSensitive,
            context,
        );
        let actual = record_actual(&result);
        if let Ok(d) = &result {
            assert!(matches!(
                d.kind(),
                MarkerAcceptKindV2::UpgradeV2 {
                    previous_sequence: 1,
                    new_sequence: 2
                }
            ));
        } else {
            panic!("H3: expected Ok rotate decision, got {:?}", result);
        }
        let post_sha = sha256_hex_of(&marker_path);
        assert_eq!(
            pre_sha, post_sha,
            "H3: seed marker bytes must remain unchanged before post-commit boundary"
        );
        out.push(ScenarioRecord {
            id,
            policy: "RequiredForLifecycleSensitive",
            load_status,
            expected_label: "Accepted (UpgradeV2 1->2); load_status=Available(GenesisBound,Rotate)",
            expected_match: r"Ok\(.*UpgradeV2.*previous_sequence:\s*1.*new_sequence:\s*2",
            actual,
            sidecar_path,
            sidecar_sha,
            marker_pre_sha: Some(pre_sha),
            marker_post_sha: Some(post_sha),
            marker_path,
            expect_no_mutation: true,
        });
    }

    // -----------------------------------------------------------------
    // H4 — A7: idempotent re-presentation of the same proof-carrying
    //      sidecar from H3 must produce a deterministically-equivalent
    //      accept decision. Pure-gate property; no marker mutation.
    // -----------------------------------------------------------------
    {
        let id = "H4_a7_available_idempotent_replay_accept";
        let dir = out_dir.join("scenarios").join(id);
        fs::create_dir_all(&dir).expect("h4 dir");
        let sidecar_path = dir.join("sidecar.json");
        let marker_path = authority_state_file_path(&dir);
        let r = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None);
        let ratified = h.verify_v2(&r);
        let candidate =
            h.derive_candidate(&gh, &r, &ratified, AuthorityStateUpdateSource::StartupLoad);
        let proof = good_proof(
            &h,
            &candidate,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::ActivateInitial,
        );
        let wire = GovernanceAuthorityProofWire::from_governance_authority_proof(&proof);
        let bytes = build_sidecar_json(&r, Some(&wire));
        fs::write(&sidecar_path, &bytes).expect("write sidecar");
        let sidecar_sha = sha256_hex_of(&sidecar_path);

        let loaded = load_v2_ratification_sidecar_with_governance_proof_from_path(&sidecar_path)
            .expect("load");
        let load_status = load_status_label(&loaded.governance_proof);
        let ratified_loaded = h.verify_v2(&loaded.ratification);
        let verifier = fixture_issuer_signature_verifier();
        let context_a = loaded.governance_proof.governance_proof_context(&verifier);
        let r1 = decide_v2_marker_acceptance_with_lifecycle_and_governance(
            make_inputs(
                &marker_path,
                &gh,
                &loaded.ratification,
                &ratified_loaded,
                AuthorityStateUpdateSource::StartupLoad,
            ),
            GovernanceProofPolicy::RequiredForLifecycleSensitive,
            context_a,
        )
        .expect("h4 first eval accepts");
        let context_b = loaded.governance_proof.governance_proof_context(&verifier);
        let r2 = decide_v2_marker_acceptance_with_lifecycle_and_governance(
            make_inputs(
                &marker_path,
                &gh,
                &loaded.ratification,
                &ratified_loaded,
                AuthorityStateUpdateSource::StartupLoad,
            ),
            GovernanceProofPolicy::RequiredForLifecycleSensitive,
            context_b,
        )
        .expect("h4 second eval accepts");
        assert_eq!(r1.kind(), r2.kind());
        assert_eq!(r1.candidate(), r2.candidate());
        assert_eq!(r1.should_persist(), r2.should_persist());
        assert!(!marker_path.exists(), "H4: pure gate must not persist");
        let actual = format!("Ok({:?}) == Ok({:?})", r1.kind(), r2.kind());
        out.push(ScenarioRecord {
            id,
            policy: "RequiredForLifecycleSensitive (x2 deterministic)",
            load_status,
            expected_label: "Idempotent accept; pure gate",
            expected_match: r"Ok\(FirstV2Write\) == Ok\(FirstV2Write\)",
            actual,
            sidecar_path,
            sidecar_sha,
            marker_pre_sha: None,
            marker_post_sha: None,
            marker_path,
            expect_no_mutation: true,
        });
    }

    // -----------------------------------------------------------------
    // H5 — R1: no-proof sidecar under `Required` on `Rotate` fails
    //      closed with `GovernanceAuthorityRequiredButMissing(Rotate)`.
    //      Persisted seed marker must remain byte-for-byte unchanged.
    // -----------------------------------------------------------------
    {
        let id = "H5_r1_absent_required_rotate_required_but_missing";
        let dir = out_dir.join("scenarios").join(id);
        fs::create_dir_all(&dir).expect("h5 dir");
        let sidecar_path = dir.join("sidecar.json");
        let marker_path = authority_state_file_path(&dir);

        let r1 = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None);
        let ratified1 = h.verify_v2(&r1);
        let d1 = decide_v2_marker_acceptance_with_lifecycle_and_governance(
            make_inputs(
                &marker_path,
                &gh,
                &r1,
                &ratified1,
                AuthorityStateUpdateSource::StartupLoad,
            ),
            GovernanceProofPolicy::NotRequired,
            GovernanceProofContext::Unavailable,
        )
        .expect("h5 seed");
        persist_accepted_v2_marker_after_commit_boundary(&d1).expect("h5 persist");
        let pre_sha = sha256_hex_of(&marker_path);

        let r2 = h.build_v2(
            &h.signing_pk_b,
            2,
            BundleSigningRatificationV2Action::Rotate,
            Some(qbind_ledger::pqc_public_key_fingerprint(&h.signing_pk_a)),
        );
        let bytes = build_sidecar_json(&r2, None);
        fs::write(&sidecar_path, &bytes).expect("write no-proof rotate sidecar");
        let sidecar_sha = sha256_hex_of(&sidecar_path);
        let loaded = load_v2_ratification_sidecar_with_governance_proof_from_path(&sidecar_path)
            .expect("load");
        assert!(loaded.governance_proof.is_absent());
        let load_status = load_status_label(&loaded.governance_proof);
        let ratified2 = h.verify_v2(&loaded.ratification);
        let verifier = fixture_issuer_signature_verifier();
        let context = loaded.governance_proof.governance_proof_context(&verifier);
        let result = decide_v2_marker_acceptance_with_lifecycle_and_governance(
            make_inputs(
                &marker_path,
                &gh,
                &loaded.ratification,
                &ratified2,
                AuthorityStateUpdateSource::ReloadApply,
            ),
            GovernanceProofPolicy::RequiredForLifecycleSensitive,
            context,
        );
        let actual = record_actual(&result);
        match &result {
            Err(MutatingSurfaceMarkerV2Error::GovernanceAuthorityRequiredButMissing {
                action: LocalLifecycleAction::Rotate,
            }) => {}
            other => panic!(
                "H5: expected GovernanceAuthorityRequiredButMissing(Rotate), got {:?}",
                other
            ),
        }
        let post_sha = sha256_hex_of(&marker_path);
        assert_eq!(
            pre_sha, post_sha,
            "H5: seed marker bytes must remain byte-for-byte untouched on RequiredButMissing"
        );
        out.push(ScenarioRecord {
            id,
            policy: "RequiredForLifecycleSensitive",
            load_status,
            expected_label: "GovernanceAuthorityRequiredButMissing(Rotate); no mutation",
            expected_match: r"Err\(GovernanceAuthorityRequiredButMissing\s*\{\s*action:\s*Rotate",
            actual,
            sidecar_path,
            sidecar_sha,
            marker_pre_sha: Some(pre_sha),
            marker_post_sha: Some(post_sha),
            marker_path,
            expect_no_mutation: true,
        });
    }

    // -----------------------------------------------------------------
    // H6 — R2: malformed `governance_authority_proof` sibling under
    //      `Required` on `Rotate` fails closed. The Run 167 loader maps
    //      `Malformed` to `Unavailable` via
    //      `governance_proof_context`, so the gate fails closed with
    //      `GovernanceAuthorityRequiredButMissing(Rotate)`. No mutation.
    //      The wire-level parse error is captured in the loader log.
    // -----------------------------------------------------------------
    {
        let id = "H6_r2_malformed_required_rotate_fail_closed";
        let dir = out_dir.join("scenarios").join(id);
        fs::create_dir_all(&dir).expect("h6 dir");
        let sidecar_path = dir.join("sidecar.json");
        let marker_path = authority_state_file_path(&dir);

        let r1 = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None);
        let ratified1 = h.verify_v2(&r1);
        let d1 = decide_v2_marker_acceptance_with_lifecycle_and_governance(
            make_inputs(
                &marker_path,
                &gh,
                &r1,
                &ratified1,
                AuthorityStateUpdateSource::StartupLoad,
            ),
            GovernanceProofPolicy::NotRequired,
            GovernanceProofContext::Unavailable,
        )
        .expect("h6 seed");
        persist_accepted_v2_marker_after_commit_boundary(&d1).expect("h6 persist");
        let pre_sha = sha256_hex_of(&marker_path);

        let r2 = h.build_v2(
            &h.signing_pk_b,
            2,
            BundleSigningRatificationV2Action::Rotate,
            Some(qbind_ledger::pqc_public_key_fingerprint(&h.signing_pk_a)),
        );
        // Malformed: schema_version=99 (unsupported).
        let bytes = build_sidecar_json_raw_sibling(
            &r2,
            serde_json::json!({
                "schema_version": 99,
                "environment": "devnet",
                "chain_id": "0x00",
                "genesis_hash": "ab",
                "authority_root_fingerprint": "ab",
                "authority_root_suite_id": 1,
                "lifecycle_action": "rotate",
                "active_bundle_signing_key_fingerprint": "ab",
                "authority_domain_sequence": 2,
                "candidate_v2_digest": "ab",
                "issuer_authority_class": "genesis-bound",
                "issuer_signature_suite_id": 1,
                "issuer_signature": "abab"
            }),
        );
        fs::write(&sidecar_path, &bytes).expect("write malformed-sibling sidecar");
        let sidecar_sha = sha256_hex_of(&sidecar_path);
        let loaded = load_v2_ratification_sidecar_with_governance_proof_from_path(&sidecar_path)
            .expect("load (loader returns Ok with Malformed status)");
        assert!(
            loaded.governance_proof.is_malformed(),
            "H6: must parse Malformed"
        );
        let load_status = load_status_label(&loaded.governance_proof);
        let ratified2 = h.verify_v2(&loaded.ratification);
        let verifier = fixture_issuer_signature_verifier();
        let context = loaded.governance_proof.governance_proof_context(&verifier);
        let result = decide_v2_marker_acceptance_with_lifecycle_and_governance(
            make_inputs(
                &marker_path,
                &gh,
                &loaded.ratification,
                &ratified2,
                AuthorityStateUpdateSource::ReloadApply,
            ),
            GovernanceProofPolicy::RequiredForLifecycleSensitive,
            context,
        );
        let actual = record_actual(&result);
        match &result {
            Err(MutatingSurfaceMarkerV2Error::GovernanceAuthorityRequiredButMissing {
                action: LocalLifecycleAction::Rotate,
            }) => {}
            other => panic!(
                "H6: expected GovernanceAuthorityRequiredButMissing(Rotate) on Malformed, got {:?}",
                other
            ),
        }
        let post_sha = sha256_hex_of(&marker_path);
        assert_eq!(
            pre_sha, post_sha,
            "H6: seed marker bytes must remain byte-for-byte untouched on Malformed→Required"
        );
        out.push(ScenarioRecord {
            id,
            policy: "RequiredForLifecycleSensitive",
            load_status,
            expected_label: "GovernanceAuthorityRequiredButMissing(Rotate) [Malformed→Unavailable]; no mutation",
            expected_match: r"Err\(GovernanceAuthorityRequiredButMissing\s*\{\s*action:\s*Rotate",
            actual,
            sidecar_path,
            sidecar_sha,
            marker_pre_sha: Some(pre_sha),
            marker_post_sha: Some(post_sha),
            marker_path,
            expect_no_mutation: true,
        });
    }

    // -----------------------------------------------------------------
    // H7 — R10: invalid issuer signature on a proof-carrying sidecar
    //      under `Required` on `ActivateInitial`. Loader yields
    //      `Available`; gate yields `GovernanceAuthorityRejected(
    //      InvalidIssuerSignature{..})`. No mutation.
    // -----------------------------------------------------------------
    {
        let id = "H7_r10_available_invalid_signature_rejected";
        let dir = out_dir.join("scenarios").join(id);
        fs::create_dir_all(&dir).expect("h7 dir");
        let sidecar_path = dir.join("sidecar.json");
        let marker_path = authority_state_file_path(&dir);
        let r = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None);
        let ratified = h.verify_v2(&r);
        let candidate =
            h.derive_candidate(&gh, &r, &ratified, AuthorityStateUpdateSource::StartupLoad);
        let mut proof = good_proof(
            &h,
            &candidate,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::ActivateInitial,
        );
        proof.issuer_signature = b"tampered-not-canonical-bytes".to_vec();
        let wire = GovernanceAuthorityProofWire::from_governance_authority_proof(&proof);
        let bytes = build_sidecar_json(&r, Some(&wire));
        fs::write(&sidecar_path, &bytes).expect("write tampered-proof sidecar");
        let sidecar_sha = sha256_hex_of(&sidecar_path);
        let loaded = load_v2_ratification_sidecar_with_governance_proof_from_path(&sidecar_path)
            .expect("load");
        assert!(loaded.governance_proof.is_available());
        let load_status = load_status_label(&loaded.governance_proof);
        let ratified_loaded = h.verify_v2(&loaded.ratification);
        let verifier = fixture_issuer_signature_verifier();
        let context = loaded.governance_proof.governance_proof_context(&verifier);
        let result = decide_v2_marker_acceptance_with_lifecycle_and_governance(
            make_inputs(
                &marker_path,
                &gh,
                &loaded.ratification,
                &ratified_loaded,
                AuthorityStateUpdateSource::StartupLoad,
            ),
            GovernanceProofPolicy::RequiredForLifecycleSensitive,
            context,
        );
        let actual = record_actual(&result);
        match &result {
            Err(MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected(
                GovernanceAuthorityVerificationOutcome::InvalidIssuerSignature { .. },
            )) => {}
            other => panic!("H7: expected GovernanceAuthorityRejected(InvalidIssuerSignature), got {:?}", other),
        }
        let post_sha = if marker_path.exists() {
            Some(sha256_hex_of(&marker_path))
        } else {
            None
        };
        assert!(post_sha.is_none(), "H7: rejected gate must not write marker");
        out.push(ScenarioRecord {
            id,
            policy: "RequiredForLifecycleSensitive",
            load_status,
            expected_label: "GovernanceAuthorityRejected(InvalidIssuerSignature); no mutation",
            expected_match: r"Err\(GovernanceAuthorityRejected\(InvalidIssuerSignature",
            actual,
            sidecar_path,
            sidecar_sha,
            marker_pre_sha: None,
            marker_post_sha: post_sha,
            marker_path,
            expect_no_mutation: true,
        });
    }

    // -----------------------------------------------------------------
    // H8 — R5: wrong authority root fingerprint on a proof-carrying
    //      sidecar. Loader yields `Available`; gate yields
    //      `GovernanceAuthorityRejected(WrongAuthorityRoot{..})`. No
    //      mutation.
    // -----------------------------------------------------------------
    {
        let id = "H8_r5_available_wrong_authority_root_rejected";
        let dir = out_dir.join("scenarios").join(id);
        fs::create_dir_all(&dir).expect("h8 dir");
        let sidecar_path = dir.join("sidecar.json");
        let marker_path = authority_state_file_path(&dir);
        let r = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None);
        let ratified = h.verify_v2(&r);
        let candidate =
            h.derive_candidate(&gh, &r, &ratified, AuthorityStateUpdateSource::StartupLoad);
        let mut proof = good_proof(
            &h,
            &candidate,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::ActivateInitial,
        );
        // Tamper authority_root_fingerprint to a structurally-valid but
        // wrong value of the same length.
        proof.authority_root_fingerprint = "ff".repeat(proof.authority_root_fingerprint.len() / 2);
        let wire = GovernanceAuthorityProofWire::from_governance_authority_proof(&proof);
        let bytes = build_sidecar_json(&r, Some(&wire));
        fs::write(&sidecar_path, &bytes).expect("write wrong-root sidecar");
        let sidecar_sha = sha256_hex_of(&sidecar_path);
        let loaded = load_v2_ratification_sidecar_with_governance_proof_from_path(&sidecar_path)
            .expect("load");
        assert!(loaded.governance_proof.is_available());
        let load_status = load_status_label(&loaded.governance_proof);
        let ratified_loaded = h.verify_v2(&loaded.ratification);
        let verifier = fixture_issuer_signature_verifier();
        let context = loaded.governance_proof.governance_proof_context(&verifier);
        let result = decide_v2_marker_acceptance_with_lifecycle_and_governance(
            make_inputs(
                &marker_path,
                &gh,
                &loaded.ratification,
                &ratified_loaded,
                AuthorityStateUpdateSource::StartupLoad,
            ),
            GovernanceProofPolicy::RequiredForLifecycleSensitive,
            context,
        );
        let actual = record_actual(&result);
        match &result {
            Err(MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected(
                GovernanceAuthorityVerificationOutcome::WrongAuthorityRoot { .. },
            )) => {}
            other => panic!("H8: expected GovernanceAuthorityRejected(WrongAuthorityRoot), got {:?}", other),
        }
        let post_sha = if marker_path.exists() {
            Some(sha256_hex_of(&marker_path))
        } else {
            None
        };
        assert!(post_sha.is_none(), "H8: rejected gate must not write marker");
        out.push(ScenarioRecord {
            id,
            policy: "RequiredForLifecycleSensitive",
            load_status,
            expected_label: "GovernanceAuthorityRejected(WrongAuthorityRoot); no mutation",
            expected_match: r"Err\(GovernanceAuthorityRejected\(WrongAuthorityRoot",
            actual,
            sidecar_path,
            sidecar_sha,
            marker_pre_sha: None,
            marker_post_sha: post_sha,
            marker_path,
            expect_no_mutation: true,
        });
    }

    // -----------------------------------------------------------------
    // H9 — R7: wrong lifecycle action on a proof-carrying sidecar.
    //      Sidecar is Ratify (ActivateInitial) but proof declares
    //      Rotate. Loader yields `Available`; gate yields
    //      `GovernanceAuthorityRejected(WrongLifecycleAction{..})`. No
    //      mutation.
    // -----------------------------------------------------------------
    {
        let id = "H9_r7_available_wrong_lifecycle_action_rejected";
        let dir = out_dir.join("scenarios").join(id);
        fs::create_dir_all(&dir).expect("h9 dir");
        let sidecar_path = dir.join("sidecar.json");
        let marker_path = authority_state_file_path(&dir);
        let r = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None);
        let ratified = h.verify_v2(&r);
        let candidate =
            h.derive_candidate(&gh, &r, &ratified, AuthorityStateUpdateSource::StartupLoad);
        // Build a Rotate-action proof for an ActivateInitial candidate
        // (mismatched lifecycle).
        let mut proof = good_proof(
            &h,
            &candidate,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::ActivateInitial,
        );
        proof.lifecycle_action = LocalLifecycleAction::Rotate;
        // Recompute issuer_signature so the binding-mismatch failure
        // surfaces as `WrongLifecycleAction`, not `InvalidIssuerSignature`.
        proof.issuer_signature = fixture_issuer_signature(
            proof.issuer_authority_class,
            &proof.authority_root_fingerprint,
            &proof.candidate_v2_digest,
            proof.authority_domain_sequence,
        );
        let wire = GovernanceAuthorityProofWire::from_governance_authority_proof(&proof);
        let bytes = build_sidecar_json(&r, Some(&wire));
        fs::write(&sidecar_path, &bytes).expect("write wrong-action sidecar");
        let sidecar_sha = sha256_hex_of(&sidecar_path);
        let loaded = load_v2_ratification_sidecar_with_governance_proof_from_path(&sidecar_path)
            .expect("load");
        assert!(loaded.governance_proof.is_available());
        let load_status = load_status_label(&loaded.governance_proof);
        let ratified_loaded = h.verify_v2(&loaded.ratification);
        let verifier = fixture_issuer_signature_verifier();
        let context = loaded.governance_proof.governance_proof_context(&verifier);
        let result = decide_v2_marker_acceptance_with_lifecycle_and_governance(
            make_inputs(
                &marker_path,
                &gh,
                &loaded.ratification,
                &ratified_loaded,
                AuthorityStateUpdateSource::StartupLoad,
            ),
            GovernanceProofPolicy::RequiredForLifecycleSensitive,
            context,
        );
        let actual = record_actual(&result);
        match &result {
            Err(MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected(
                GovernanceAuthorityVerificationOutcome::WrongLifecycleAction { .. },
            )) => {}
            other => panic!("H9: expected GovernanceAuthorityRejected(WrongLifecycleAction), got {:?}", other),
        }
        let post_sha = if marker_path.exists() {
            Some(sha256_hex_of(&marker_path))
        } else {
            None
        };
        assert!(post_sha.is_none(), "H9: rejected gate must not write marker");
        out.push(ScenarioRecord {
            id,
            policy: "RequiredForLifecycleSensitive",
            load_status,
            expected_label: "GovernanceAuthorityRejected(WrongLifecycleAction); no mutation",
            expected_match: r"Err\(GovernanceAuthorityRejected\(WrongLifecycleAction",
            actual,
            sidecar_path,
            sidecar_sha,
            marker_pre_sha: None,
            marker_post_sha: post_sha,
            marker_path,
            expect_no_mutation: true,
        });
    }

    // -----------------------------------------------------------------
    // H10 — R8: wrong candidate digest on a proof-carrying sidecar.
    //       Loader yields `Available`; gate yields
    //       `GovernanceAuthorityRejected(WrongCandidateDigest{..})`.
    //       No mutation.
    // -----------------------------------------------------------------
    {
        let id = "H10_r8_available_wrong_candidate_digest_rejected";
        let dir = out_dir.join("scenarios").join(id);
        fs::create_dir_all(&dir).expect("h10 dir");
        let sidecar_path = dir.join("sidecar.json");
        let marker_path = authority_state_file_path(&dir);
        let r = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None);
        let ratified = h.verify_v2(&r);
        let candidate =
            h.derive_candidate(&gh, &r, &ratified, AuthorityStateUpdateSource::StartupLoad);
        let mut proof = good_proof(
            &h,
            &candidate,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::ActivateInitial,
        );
        // Tamper candidate digest to a structurally-valid but wrong value.
        let bad_digest = "cd".repeat(proof.candidate_v2_digest.len() / 2);
        proof.candidate_v2_digest = bad_digest;
        proof.issuer_signature = fixture_issuer_signature(
            proof.issuer_authority_class,
            &proof.authority_root_fingerprint,
            &proof.candidate_v2_digest,
            proof.authority_domain_sequence,
        );
        let wire = GovernanceAuthorityProofWire::from_governance_authority_proof(&proof);
        let bytes = build_sidecar_json(&r, Some(&wire));
        fs::write(&sidecar_path, &bytes).expect("write wrong-digest sidecar");
        let sidecar_sha = sha256_hex_of(&sidecar_path);
        let loaded = load_v2_ratification_sidecar_with_governance_proof_from_path(&sidecar_path)
            .expect("load");
        let load_status = load_status_label(&loaded.governance_proof);
        let ratified_loaded = h.verify_v2(&loaded.ratification);
        let verifier = fixture_issuer_signature_verifier();
        let context = loaded.governance_proof.governance_proof_context(&verifier);
        let result = decide_v2_marker_acceptance_with_lifecycle_and_governance(
            make_inputs(
                &marker_path,
                &gh,
                &loaded.ratification,
                &ratified_loaded,
                AuthorityStateUpdateSource::StartupLoad,
            ),
            GovernanceProofPolicy::RequiredForLifecycleSensitive,
            context,
        );
        let actual = record_actual(&result);
        match &result {
            Err(MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected(
                GovernanceAuthorityVerificationOutcome::WrongCandidateDigest { .. },
            )) => {}
            other => panic!("H10: expected GovernanceAuthorityRejected(WrongCandidateDigest), got {:?}", other),
        }
        let post_sha = if marker_path.exists() {
            Some(sha256_hex_of(&marker_path))
        } else {
            None
        };
        assert!(post_sha.is_none(), "H10: rejected gate must not write marker");
        out.push(ScenarioRecord {
            id,
            policy: "RequiredForLifecycleSensitive",
            load_status,
            expected_label: "GovernanceAuthorityRejected(WrongCandidateDigest); no mutation",
            expected_match: r"Err\(GovernanceAuthorityRejected\(WrongCandidateDigest",
            actual,
            sidecar_path,
            sidecar_sha,
            marker_pre_sha: None,
            marker_post_sha: post_sha,
            marker_path,
            expect_no_mutation: true,
        });
    }

    // -----------------------------------------------------------------
    // H11 — R9: wrong authority-domain sequence. Loader yields
    //       `Available`; gate yields `GovernanceAuthorityRejected(
    //       WrongAuthoritySequence{..})`. No mutation.
    // -----------------------------------------------------------------
    {
        let id = "H11_r9_available_wrong_authority_sequence_rejected";
        let dir = out_dir.join("scenarios").join(id);
        fs::create_dir_all(&dir).expect("h11 dir");
        let sidecar_path = dir.join("sidecar.json");
        let marker_path = authority_state_file_path(&dir);
        let r = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None);
        let ratified = h.verify_v2(&r);
        let candidate =
            h.derive_candidate(&gh, &r, &ratified, AuthorityStateUpdateSource::StartupLoad);
        let mut proof = good_proof(
            &h,
            &candidate,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::ActivateInitial,
        );
        proof.authority_domain_sequence = proof.authority_domain_sequence.wrapping_add(7);
        proof.issuer_signature = fixture_issuer_signature(
            proof.issuer_authority_class,
            &proof.authority_root_fingerprint,
            &proof.candidate_v2_digest,
            proof.authority_domain_sequence,
        );
        let wire = GovernanceAuthorityProofWire::from_governance_authority_proof(&proof);
        let bytes = build_sidecar_json(&r, Some(&wire));
        fs::write(&sidecar_path, &bytes).expect("write wrong-seq sidecar");
        let sidecar_sha = sha256_hex_of(&sidecar_path);
        let loaded = load_v2_ratification_sidecar_with_governance_proof_from_path(&sidecar_path)
            .expect("load");
        let load_status = load_status_label(&loaded.governance_proof);
        let ratified_loaded = h.verify_v2(&loaded.ratification);
        let verifier = fixture_issuer_signature_verifier();
        let context = loaded.governance_proof.governance_proof_context(&verifier);
        let result = decide_v2_marker_acceptance_with_lifecycle_and_governance(
            make_inputs(
                &marker_path,
                &gh,
                &loaded.ratification,
                &ratified_loaded,
                AuthorityStateUpdateSource::StartupLoad,
            ),
            GovernanceProofPolicy::RequiredForLifecycleSensitive,
            context,
        );
        let actual = record_actual(&result);
        match &result {
            Err(MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected(
                GovernanceAuthorityVerificationOutcome::WrongAuthoritySequence { .. },
            )) => {}
            other => panic!("H11: expected GovernanceAuthorityRejected(WrongAuthoritySequence), got {:?}", other),
        }
        let post_sha = if marker_path.exists() {
            Some(sha256_hex_of(&marker_path))
        } else {
            None
        };
        assert!(post_sha.is_none(), "H11: rejected gate must not write marker");
        out.push(ScenarioRecord {
            id,
            policy: "RequiredForLifecycleSensitive",
            load_status,
            expected_label: "GovernanceAuthorityRejected(WrongAuthoritySequence); no mutation",
            expected_match: r"Err\(GovernanceAuthorityRejected\(WrongAuthoritySequence",
            actual,
            sidecar_path,
            sidecar_sha,
            marker_pre_sha: None,
            marker_post_sha: post_sha,
            marker_path,
            expect_no_mutation: true,
        });
    }

    // -----------------------------------------------------------------
    // H12 — R15: `OnChainGovernance` issuer class on a proof-carrying
    //       sidecar. Loader yields `Available` (round-trips through the
    //       wire); gate yields `GovernanceAuthorityRejected(
    //       UnsupportedOnChainGovernance)`. No mutation.
    // -----------------------------------------------------------------
    {
        let id = "H12_r15_available_on_chain_governance_unsupported";
        let dir = out_dir.join("scenarios").join(id);
        fs::create_dir_all(&dir).expect("h12 dir");
        let sidecar_path = dir.join("sidecar.json");
        let marker_path = authority_state_file_path(&dir);
        let r = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None);
        let ratified = h.verify_v2(&r);
        let candidate =
            h.derive_candidate(&gh, &r, &ratified, AuthorityStateUpdateSource::StartupLoad);
        let mut proof = good_proof(
            &h,
            &candidate,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::ActivateInitial,
        );
        proof.issuer_authority_class = GovernanceAuthorityClass::OnChainGovernance;
        // Recompute fixture signature for the new class so the failure
        // is class-unsupported, not InvalidIssuerSignature.
        proof.issuer_signature = fixture_issuer_signature(
            proof.issuer_authority_class,
            &proof.authority_root_fingerprint,
            &proof.candidate_v2_digest,
            proof.authority_domain_sequence,
        );
        let wire = GovernanceAuthorityProofWire::from_governance_authority_proof(&proof);
        let bytes = build_sidecar_json(&r, Some(&wire));
        fs::write(&sidecar_path, &bytes).expect("write on-chain-gov sidecar");
        let sidecar_sha = sha256_hex_of(&sidecar_path);
        let loaded = load_v2_ratification_sidecar_with_governance_proof_from_path(&sidecar_path)
            .expect("load");
        assert!(loaded.governance_proof.is_available());
        let load_status = load_status_label(&loaded.governance_proof);
        let ratified_loaded = h.verify_v2(&loaded.ratification);
        let verifier = fixture_issuer_signature_verifier();
        let context = loaded.governance_proof.governance_proof_context(&verifier);
        let result = decide_v2_marker_acceptance_with_lifecycle_and_governance(
            make_inputs(
                &marker_path,
                &gh,
                &loaded.ratification,
                &ratified_loaded,
                AuthorityStateUpdateSource::StartupLoad,
            ),
            GovernanceProofPolicy::RequiredForLifecycleSensitive,
            context,
        );
        let actual = record_actual(&result);
        match &result {
            Err(MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected(
                GovernanceAuthorityVerificationOutcome::UnsupportedOnChainGovernance,
            )) => {}
            other => panic!("H12: expected GovernanceAuthorityRejected(UnsupportedOnChainGovernance), got {:?}", other),
        }
        let post_sha = if marker_path.exists() {
            Some(sha256_hex_of(&marker_path))
        } else {
            None
        };
        assert!(post_sha.is_none(), "H12: rejected gate must not write marker");
        out.push(ScenarioRecord {
            id,
            policy: "RequiredForLifecycleSensitive",
            load_status,
            expected_label: "GovernanceAuthorityRejected(UnsupportedOnChainGovernance); no mutation",
            expected_match: r"Err\(GovernanceAuthorityRejected\(UnsupportedOnChainGovernance",
            actual,
            sidecar_path,
            sidecar_sha,
            marker_pre_sha: None,
            marker_post_sha: post_sha,
            marker_path,
            expect_no_mutation: true,
        });
    }

    // -----------------------------------------------------------------
    // H13 — R16-equivalent: "local operator config alone" cannot encode
    //       a proof. The wire boundary rejects empty `issuer_signature`
    //       as `EmptyIssuerSignature`; the loader maps the parse error
    //       to `Malformed`, and the gate fail-closes under `Required`.
    //       This documents that no in-band path lets an operator inject
    //       a non-authority proof through the existing loader.
    // -----------------------------------------------------------------
    {
        let id = "H13_r16_empty_issuer_signature_malformed_fail_closed";
        let dir = out_dir.join("scenarios").join(id);
        fs::create_dir_all(&dir).expect("h13 dir");
        let sidecar_path = dir.join("sidecar.json");
        let marker_path = authority_state_file_path(&dir);

        let r1 = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None);
        let ratified1 = h.verify_v2(&r1);
        let d1 = decide_v2_marker_acceptance_with_lifecycle_and_governance(
            make_inputs(
                &marker_path,
                &gh,
                &r1,
                &ratified1,
                AuthorityStateUpdateSource::StartupLoad,
            ),
            GovernanceProofPolicy::NotRequired,
            GovernanceProofContext::Unavailable,
        )
        .expect("h13 seed");
        persist_accepted_v2_marker_after_commit_boundary(&d1).expect("h13 persist");
        let pre_sha = sha256_hex_of(&marker_path);

        let r2 = h.build_v2(
            &h.signing_pk_b,
            2,
            BundleSigningRatificationV2Action::Rotate,
            Some(qbind_ledger::pqc_public_key_fingerprint(&h.signing_pk_a)),
        );
        // Splice a structurally-valid wire object with an EMPTY issuer
        // signature ("" hex string).
        let bytes = build_sidecar_json_raw_sibling(
            &r2,
            serde_json::json!({
                "schema_version": 1,
                "environment": "devnet",
                "chain_id": h.chain_id_str.clone(),
                "genesis_hash": gh.clone(),
                "authority_root_fingerprint": h.root_fp(),
                "authority_root_suite_id": GENESIS_AUTHORITY_SUITE_ML_DSA_44,
                "lifecycle_action": "rotate",
                "active_bundle_signing_key_fingerprint": "ab",
                "authority_domain_sequence": 2,
                "candidate_v2_digest": "ab",
                "issuer_authority_class": "genesis-bound",
                "issuer_signature_suite_id": PQC_GOVERNANCE_ISSUER_SUITE_ML_DSA_44,
                "issuer_signature": ""
            }),
        );
        fs::write(&sidecar_path, &bytes).expect("write empty-sig sidecar");
        let sidecar_sha = sha256_hex_of(&sidecar_path);
        let loaded = load_v2_ratification_sidecar_with_governance_proof_from_path(&sidecar_path)
            .expect("loader returns Ok with Malformed status");
        assert!(loaded.governance_proof.is_malformed());
        let load_status = load_status_label(&loaded.governance_proof);
        let ratified2 = h.verify_v2(&loaded.ratification);
        let verifier = fixture_issuer_signature_verifier();
        let context = loaded.governance_proof.governance_proof_context(&verifier);
        let result = decide_v2_marker_acceptance_with_lifecycle_and_governance(
            make_inputs(
                &marker_path,
                &gh,
                &loaded.ratification,
                &ratified2,
                AuthorityStateUpdateSource::ReloadApply,
            ),
            GovernanceProofPolicy::RequiredForLifecycleSensitive,
            context,
        );
        let actual = record_actual(&result);
        match &result {
            Err(MutatingSurfaceMarkerV2Error::GovernanceAuthorityRequiredButMissing {
                action: LocalLifecycleAction::Rotate,
            }) => {}
            other => panic!("H13: expected GovernanceAuthorityRequiredButMissing(Rotate), got {:?}", other),
        }
        let post_sha = sha256_hex_of(&marker_path);
        assert_eq!(
            pre_sha, post_sha,
            "H13: seed marker bytes must remain byte-for-byte untouched"
        );
        out.push(ScenarioRecord {
            id,
            policy: "RequiredForLifecycleSensitive",
            load_status,
            expected_label: "GovernanceAuthorityRequiredButMissing(Rotate) [Malformed:EmptyIssuerSignature]; no mutation",
            expected_match: r"Err\(GovernanceAuthorityRequiredButMissing\s*\{\s*action:\s*Rotate",
            actual,
            sidecar_path,
            sidecar_sha,
            marker_pre_sha: Some(pre_sha),
            marker_post_sha: Some(post_sha),
            marker_path,
            expect_no_mutation: true,
        });
    }

    out
}

fn main() {
    let arg = env::args()
        .nth(1)
        .expect("usage: run_168_governance_proof_carrier_release_binary_helper <OUT_DIR>");
    let out_dir = PathBuf::from(&arg);
    fs::create_dir_all(&out_dir).expect("create OUT_DIR");
    let records = run();

    let mut manifest = String::new();
    let mut expected_outcomes = String::new();
    let mut actual_outcomes = String::new();
    for r in &records {
        let dir = out_dir.join("scenarios").join(r.id);
        fs::create_dir_all(&dir).expect("scenario dir");
        write_text(&dir.join("policy.txt"), r.policy);
        write_text(&dir.join("load_status.txt"), &r.load_status);
        write_text(&dir.join("expected.txt"), r.expected_label);
        write_text(&dir.join("actual.txt"), &r.actual);
        write_text(&dir.join("sidecar.sha256"), &r.sidecar_sha);
        write_text(
            &dir.join("sidecar_path.txt"),
            &r.sidecar_path.display().to_string(),
        );
        write_text(
            &dir.join("marker_path.txt"),
            &r.marker_path.display().to_string(),
        );
        if let Some(sha) = &r.marker_pre_sha {
            write_text(&dir.join("marker_pre.sha256"), sha);
        }
        match &r.marker_post_sha {
            Some(sha) => write_text(&dir.join("marker_post.sha256"), sha),
            None => write_text(&dir.join("marker_post.sha256"), ""),
        }
        if r.expect_no_mutation {
            write_text(
                &dir.join("no_mutation_invariant.txt"),
                "asserted: pre==post (seeded) or post=ABSENT (unseeded)\n",
            );
        }
        manifest.push_str(&format!(
            "{}\t{}\t{}\n",
            r.id, r.expected_label, r.expected_match
        ));
        expected_outcomes.push_str(&format!(
            "{}: policy={} load_status={} -> {}\n",
            r.id, r.policy, r.load_status, r.expected_label
        ));
        actual_outcomes.push_str(&format!("{}: {}\n", r.id, r.actual));
    }
    write_text(&out_dir.join("manifest.txt"), &manifest);
    write_text(&out_dir.join("expected_outcomes.txt"), &expected_outcomes);
    write_text(&out_dir.join("actual_outcomes.txt"), &actual_outcomes);

    println!(
        "[run-168-helper] OK — {} scenarios written under {}",
        records.len(),
        out_dir.display()
    );
}
