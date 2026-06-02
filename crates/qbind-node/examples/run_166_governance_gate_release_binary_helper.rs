//! Run 166 — release-built helper exercising the Run 165 governance gate
//! through the production marker-decision surface
//! (`pqc_authority_marker_acceptance::decide_v2_marker_acceptance_with_lifecycle_and_governance`).
//!
//! After Run 165 wired the Run 163 governance authority verifier into the
//! shared v2 lifecycle / marker-decision helper, every mutating v2 surface
//! (process-start reload-apply, `--p2p-trust-bundle` startup, SIGHUP
//! live-reload, peer-driven drain via `ProductionV2MarkerCoordinator`)
//! routes through that helper. The four production callers today supply
//! `GovernanceProofPolicy::NotRequired` and
//! `GovernanceProofContext::Unavailable` because the v2 ratification /
//! authority-marker wire material does not yet carry governance-proof
//! fields (documented schema gap; see Run 165 evidence). Run 166's
//! release-binary task is to honestly evidence:
//!
//!   * the `NotRequired` compatibility path remains green on the real
//!     release binary (`H1`/`H2`);
//!   * the `RequiredForLifecycleSensitive` policy correctly fail-closes
//!     with `MutatingSurfaceMarkerV2Error::GovernanceAuthorityRequiredButMissing`
//!     when the production wire cannot carry a proof (`H3`);
//!   * `ActivateInitial` remains governance-optional under both policies
//!     (genesis-bound first activation, `H4`);
//!   * a supplied valid governance proof accepts the lifecycle-sensitive
//!     transition (`H5`);
//!   * a supplied invalid governance proof rejects with
//!     `MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected` and
//!     produces no marker write (`H6`);
//!   * the gate is deterministic / side-effect free and acceptance carries
//!     no MainNet-apply capability (`H7`);
//!   * persisted seed marker bytes are byte-for-byte untouched on every
//!     rejection (`H3`/`H6`).
//!
//! This helper is a release-built binary
//! (`cargo build --release -p qbind-node --example
//! run_166_governance_gate_release_binary_helper`). It links the same
//! `decide_v2_marker_acceptance_with_lifecycle_and_governance` symbol
//! that `pqc_live_trust_reload.rs`, `pqc_peer_candidate_apply.rs`, and
//! `main.rs` link in `target/release/qbind-node`, so a passing scenario
//! here is honest release-binary evidence that the production
//! marker-decision surface enforces the Run 165 governance gate.
//!
//! Run 166 is release-binary EVIDENCE / ENFORCEMENT only. This helper:
//!   * does NOT enable MainNet peer-driven apply;
//!   * does NOT mutate any live trust state;
//!   * does NOT open a P2P socket;
//!   * does NOT introduce any wire / marker / sequence / trust-bundle
//!     schema change;
//!   * does NOT implement governance execution, on-chain governance,
//!     KMS/HSM custody, or validator-set rotation;
//!   * persists at most an ephemeral seed v2 marker under `<OUT_DIR>/`
//!     for scenarios that need a persisted prior generation, and only
//!     ever via the existing
//!     `persist_accepted_v2_marker_after_commit_boundary` helper after a
//!     `decide_v2_marker_acceptance_with_lifecycle_and_governance` accept.
//!
//! Usage:
//! ```text
//! run_166_governance_gate_release_binary_helper <OUT_DIR>
//! ```
//!
//! Writes:
//! ```text
//! <OUT_DIR>/manifest.txt              # one line per scenario: <id>\t<expected_label>\t<expected_match>
//! <OUT_DIR>/expected_outcomes.txt     # human-readable map
//! <OUT_DIR>/actual_outcomes.txt       # actual typed-outcome Debug dumps
//! <OUT_DIR>/scenarios/<id>/policy.txt
//! <OUT_DIR>/scenarios/<id>/context.txt
//! <OUT_DIR>/scenarios/<id>/expected.txt
//! <OUT_DIR>/scenarios/<id>/actual.txt
//! <OUT_DIR>/scenarios/<id>/marker_pre.sha256   # if the scenario seeded a marker
//! <OUT_DIR>/scenarios/<id>/marker_post.sha256  # always — proves no mutation on rejection
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
    GovernanceAuthorityProof, GovernanceProofContext, GovernanceProofPolicy,
    PQC_GOVERNANCE_ISSUER_SUITE_ML_DSA_44,
};
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
    // Use sha3 here only because it is already a transitive dep; we just need
    // a deterministic content fingerprint for the harness, not a security
    // boundary. The harness records SHA-256 of binaries via `sha256sum`
    // separately.
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

/// Encapsulates one scenario record.
struct ScenarioRecord {
    id: &'static str,
    policy: &'static str,
    context: &'static str,
    expected_label: &'static str,
    expected_match: &'static str,
    actual: String,
    marker_pre_sha: Option<String>,
    marker_post_sha: Option<String>,
    marker_path: PathBuf,
    /// True iff the scenario expected to leave the marker bytes
    /// byte-for-byte untouched (every reject scenario must satisfy this;
    /// the H1/H2/H3/H7 accept-without-persist scenarios also satisfy it
    /// because the helper itself never persists; only the seeded H6 / H5
    /// follow-up tests intentionally allow the seed to remain).
    expect_no_mutation: bool,
}

fn record_actual<T: std::fmt::Debug, E: std::fmt::Debug>(
    result: &Result<T, E>,
) -> String {
    match result {
        Ok(v) => format!("Ok({:?})", v),
        Err(e) => format!("Err({:?})", e),
    }
}

fn run() -> Vec<ScenarioRecord> {
    let mut out = Vec::new();
    let h = devnet_harness();
    let gh = h.genesis_hex();

    // Seven independent scenarios, each in its own data dir, mirroring the
    // four production-surface call sites that all link
    // `decide_v2_marker_acceptance_with_lifecycle_and_governance`. The
    // helper writes only when a scenario explicitly requires a seeded
    // generation (`H3`, `H5`, `H6`, `H7`).
    let arg = env::args().nth(1).expect("usage: run_166_helper <OUT_DIR>");
    let out_dir = PathBuf::from(arg);
    fs::create_dir_all(&out_dir).expect("create OUT_DIR");

    // -----------------------------------------------------------------
    // H1 — NotRequired + Unavailable + ActivateInitial accepted.
    //      Mirrors the validation-only / NotRequired compatibility path
    //      every production surface uses today (A1 from the task matrix:
    //      NotRequired remains compatible, no marker mutation occurs in
    //      this helper).
    // -----------------------------------------------------------------
    {
        let id = "H1_not_required_initial_accept";
        let dir = out_dir.join("scenarios").join(id);
        fs::create_dir_all(&dir).expect("h1 dir");
        let marker_path = authority_state_file_path(&dir);
        let r = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None);
        let ratified = h.verify_v2(&r);
        let result = decide_v2_marker_acceptance_with_lifecycle_and_governance(
            make_inputs(&marker_path, &gh, &r, &ratified, AuthorityStateUpdateSource::StartupLoad),
            GovernanceProofPolicy::NotRequired,
            GovernanceProofContext::Unavailable,
        );
        let actual = record_actual(&result);
        let post_sha = if marker_path.exists() {
            Some(sha256_hex_of(&marker_path))
        } else {
            None
        };
        // Sanity: helper itself must not have written a marker.
        assert!(post_sha.is_none(), "H1: helper must not write marker before post-commit boundary");
        // Confirm typed accept kind locally (cheap structural assertion;
        // the full Debug dump goes into actual.txt for the harness).
        if let Ok(d) = &result {
            assert!(matches!(d.kind(), MarkerAcceptKindV2::FirstV2Write));
        } else {
            panic!("H1: expected Ok decision");
        }
        out.push(ScenarioRecord {
            id,
            policy: "NotRequired",
            context: "Unavailable",
            expected_label: "Accepted (FirstV2Write)",
            expected_match: r"Ok\(.*FirstV2Write",
            actual,
            marker_pre_sha: None,
            marker_post_sha: post_sha,
            marker_path,
            expect_no_mutation: true,
        });
    }

    // -----------------------------------------------------------------
    // H2 — NotRequired + Unavailable + Rotate accepted (after seed).
    //      Mirrors the mutating-equivalent NotRequired compatibility
    //      path on a lifecycle-sensitive transition (A2 from the task
    //      matrix). Demonstrates that a missing proof under NotRequired
    //      does NOT refuse a Rotate.
    // -----------------------------------------------------------------
    {
        let id = "H2_not_required_rotate_accept";
        let dir = out_dir.join("scenarios").join(id);
        fs::create_dir_all(&dir).expect("h2 dir");
        let marker_path = authority_state_file_path(&dir);
        // Seed generation A at seq 1 via NotRequired accept + post-commit persist.
        let r1 = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None);
        let ratified1 = h.verify_v2(&r1);
        let d1: MarkerAcceptDecisionV2 = decide_v2_marker_acceptance_with_lifecycle_and_governance(
            make_inputs(&marker_path, &gh, &r1, &ratified1, AuthorityStateUpdateSource::StartupLoad),
            GovernanceProofPolicy::NotRequired,
            GovernanceProofContext::Unavailable,
        )
        .expect("h2 seed accept");
        persist_accepted_v2_marker_after_commit_boundary(&d1).expect("h2 persist seed");
        let pre_sha = sha256_hex_of(&marker_path);

        // Rotate to B at seq 2 with NO proof under NotRequired — accepts.
        let r2 = h.build_v2(
            &h.signing_pk_b,
            2,
            BundleSigningRatificationV2Action::Rotate,
            Some(qbind_ledger::pqc_public_key_fingerprint(&h.signing_pk_a)),
        );
        let ratified2 = h.verify_v2(&r2);
        let result = decide_v2_marker_acceptance_with_lifecycle_and_governance(
            make_inputs(&marker_path, &gh, &r2, &ratified2, AuthorityStateUpdateSource::ReloadApply),
            GovernanceProofPolicy::NotRequired,
            GovernanceProofContext::Unavailable,
        );
        let actual = record_actual(&result);
        if let Ok(d) = &result {
            assert!(matches!(
                d.kind(),
                MarkerAcceptKindV2::UpgradeV2 { previous_sequence: 1, new_sequence: 2 }
            ));
        } else {
            panic!("H2: expected Ok rotate decision");
        }
        // Helper itself never persists past the seeded marker.
        let post_sha = sha256_hex_of(&marker_path);
        assert_eq!(pre_sha, post_sha, "H2: seed marker bytes must remain unchanged after non-persisted decision");
        out.push(ScenarioRecord {
            id,
            policy: "NotRequired",
            context: "Unavailable",
            expected_label: "Accepted (UpgradeV2 1->2)",
            expected_match: r"Ok\(.*UpgradeV2.*previous_sequence:\s*1.*new_sequence:\s*2",
            actual,
            marker_pre_sha: Some(pre_sha),
            marker_post_sha: Some(post_sha),
            marker_path,
            expect_no_mutation: true,
        });
    }

    // -----------------------------------------------------------------
    // H3 — RequiredForLifecycleSensitive + Unavailable + Rotate fails closed.
    //      Mirrors A3/A4 from the task: when the production-surface wire
    //      cannot carry a proof (`Unavailable`), a `Required` policy on a
    //      lifecycle-sensitive action MUST fail closed with
    //      `GovernanceAuthorityRequiredButMissing`. Persisted seed marker
    //      bytes MUST remain byte-for-byte untouched.
    // -----------------------------------------------------------------
    {
        let id = "H3_required_rotate_required_but_missing";
        let dir = out_dir.join("scenarios").join(id);
        fs::create_dir_all(&dir).expect("h3 dir");
        let marker_path = authority_state_file_path(&dir);

        // Seed A at seq 1 (NotRequired + Unavailable).
        let r1 = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None);
        let ratified1 = h.verify_v2(&r1);
        let d1 = decide_v2_marker_acceptance_with_lifecycle_and_governance(
            make_inputs(&marker_path, &gh, &r1, &ratified1, AuthorityStateUpdateSource::StartupLoad),
            GovernanceProofPolicy::NotRequired,
            GovernanceProofContext::Unavailable,
        )
        .expect("h3 seed accept");
        persist_accepted_v2_marker_after_commit_boundary(&d1).expect("h3 persist seed");
        let pre_sha = sha256_hex_of(&marker_path);

        // Rotate to B at seq 2 with NO proof under RequiredForLifecycleSensitive.
        let r2 = h.build_v2(
            &h.signing_pk_b,
            2,
            BundleSigningRatificationV2Action::Rotate,
            Some(qbind_ledger::pqc_public_key_fingerprint(&h.signing_pk_a)),
        );
        let ratified2 = h.verify_v2(&r2);
        let result = decide_v2_marker_acceptance_with_lifecycle_and_governance(
            make_inputs(&marker_path, &gh, &r2, &ratified2, AuthorityStateUpdateSource::ReloadApply),
            GovernanceProofPolicy::RequiredForLifecycleSensitive,
            GovernanceProofContext::Unavailable,
        );
        let actual = record_actual(&result);
        match &result {
            Err(MutatingSurfaceMarkerV2Error::GovernanceAuthorityRequiredButMissing {
                action: LocalLifecycleAction::Rotate,
            }) => {}
            other => panic!("H3: expected GovernanceAuthorityRequiredButMissing(Rotate), got {:?}", other),
        }
        let post_sha = sha256_hex_of(&marker_path);
        assert_eq!(pre_sha, post_sha, "H3: seed marker bytes must remain byte-for-byte untouched on RequiredButMissing");
        out.push(ScenarioRecord {
            id,
            policy: "RequiredForLifecycleSensitive",
            context: "Unavailable",
            expected_label: "GovernanceAuthorityRequiredButMissing(Rotate)",
            expected_match: r"Err\(GovernanceAuthorityRequiredButMissing\s*\{\s*action:\s*Rotate",
            actual,
            marker_pre_sha: Some(pre_sha),
            marker_post_sha: Some(post_sha),
            marker_path,
            expect_no_mutation: true,
        });
    }

    // -----------------------------------------------------------------
    // H4 — RequiredForLifecycleSensitive + Unavailable + ActivateInitial
    //      accepted. Genesis-bound first activation is governance-optional
    //      under both policies (Run 165 §A5 chosen-policy semantics).
    // -----------------------------------------------------------------
    {
        let id = "H4_required_initial_remains_optional";
        let dir = out_dir.join("scenarios").join(id);
        fs::create_dir_all(&dir).expect("h4 dir");
        let marker_path = authority_state_file_path(&dir);
        let r = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None);
        let ratified = h.verify_v2(&r);
        let result = decide_v2_marker_acceptance_with_lifecycle_and_governance(
            make_inputs(&marker_path, &gh, &r, &ratified, AuthorityStateUpdateSource::StartupLoad),
            GovernanceProofPolicy::RequiredForLifecycleSensitive,
            GovernanceProofContext::Unavailable,
        );
        let actual = record_actual(&result);
        if let Ok(d) = &result {
            assert!(matches!(d.kind(), MarkerAcceptKindV2::FirstV2Write));
        } else {
            panic!("H4: expected Ok decision (ActivateInitial governance-optional)");
        }
        let post_sha = if marker_path.exists() {
            Some(sha256_hex_of(&marker_path))
        } else {
            None
        };
        assert!(post_sha.is_none(), "H4: helper must not write marker before post-commit boundary");
        out.push(ScenarioRecord {
            id,
            policy: "RequiredForLifecycleSensitive",
            context: "Unavailable",
            expected_label: "Accepted (FirstV2Write, ActivateInitial governance-optional)",
            expected_match: r"Ok\(.*FirstV2Write",
            actual,
            marker_pre_sha: None,
            marker_post_sha: post_sha,
            marker_path,
            expect_no_mutation: true,
        });
    }

    // -----------------------------------------------------------------
    // H5 — RequiredForLifecycleSensitive + Supplied(good GenesisBound,
    //      Rotate) + Rotate accepted. Demonstrates that the production
    //      marker-decision surface accepts a lifecycle-sensitive action
    //      when a valid governance proof IS supplied.
    // -----------------------------------------------------------------
    {
        let id = "H5_required_rotate_supplied_accept";
        let dir = out_dir.join("scenarios").join(id);
        fs::create_dir_all(&dir).expect("h5 dir");
        let marker_path = authority_state_file_path(&dir);
        let r1 = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None);
        let ratified1 = h.verify_v2(&r1);
        let d1 = decide_v2_marker_acceptance_with_lifecycle_and_governance(
            make_inputs(&marker_path, &gh, &r1, &ratified1, AuthorityStateUpdateSource::StartupLoad),
            GovernanceProofPolicy::NotRequired,
            GovernanceProofContext::Unavailable,
        )
        .expect("h5 seed accept");
        persist_accepted_v2_marker_after_commit_boundary(&d1).expect("h5 persist seed");
        let pre_sha = sha256_hex_of(&marker_path);

        let r2 = h.build_v2(
            &h.signing_pk_b,
            2,
            BundleSigningRatificationV2Action::Rotate,
            Some(qbind_ledger::pqc_public_key_fingerprint(&h.signing_pk_a)),
        );
        let ratified2 = h.verify_v2(&r2);
        let candidate =
            h.derive_candidate(&gh, &r2, &ratified2, AuthorityStateUpdateSource::ReloadApply);
        let proof = good_proof(
            &h,
            &candidate,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::Rotate,
        );
        let verifier = fixture_issuer_signature_verifier();
        let result = decide_v2_marker_acceptance_with_lifecycle_and_governance(
            make_inputs(&marker_path, &gh, &r2, &ratified2, AuthorityStateUpdateSource::ReloadApply),
            GovernanceProofPolicy::RequiredForLifecycleSensitive,
            GovernanceProofContext::Supplied { proof: &proof, verifier: &verifier },
        );
        let actual = record_actual(&result);
        if let Ok(d) = &result {
            assert!(matches!(
                d.kind(),
                MarkerAcceptKindV2::UpgradeV2 { previous_sequence: 1, new_sequence: 2 }
            ));
        } else {
            panic!("H5: expected Ok rotate decision with supplied governance proof");
        }
        // Decision is pre-commit; helper does not persist here.
        let post_sha = sha256_hex_of(&marker_path);
        assert_eq!(pre_sha, post_sha, "H5: seed marker bytes must remain unchanged before post-commit boundary");
        out.push(ScenarioRecord {
            id,
            policy: "RequiredForLifecycleSensitive",
            context: "Supplied(GenesisBound,Rotate,good)",
            expected_label: "Accepted (UpgradeV2 1->2)",
            expected_match: r"Ok\(.*UpgradeV2.*previous_sequence:\s*1.*new_sequence:\s*2",
            actual,
            marker_pre_sha: Some(pre_sha),
            marker_post_sha: Some(post_sha),
            marker_path,
            expect_no_mutation: true,
        });
    }

    // -----------------------------------------------------------------
    // H6 — RequiredForLifecycleSensitive + Supplied(tampered) +
    //      ActivateInitial → GovernanceAuthorityRejected
    //      (InvalidIssuerSignature). No marker write.
    // -----------------------------------------------------------------
    {
        let id = "H6_required_tampered_proof_rejected";
        let dir = out_dir.join("scenarios").join(id);
        fs::create_dir_all(&dir).expect("h6 dir");
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
        proof.issuer_signature = b"tampered".to_vec();
        let verifier = fixture_issuer_signature_verifier();
        let result = decide_v2_marker_acceptance_with_lifecycle_and_governance(
            make_inputs(&marker_path, &gh, &r, &ratified, AuthorityStateUpdateSource::StartupLoad),
            GovernanceProofPolicy::RequiredForLifecycleSensitive,
            GovernanceProofContext::Supplied { proof: &proof, verifier: &verifier },
        );
        let actual = record_actual(&result);
        match &result {
            Err(MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected(_)) => {}
            other => panic!("H6: expected GovernanceAuthorityRejected, got {:?}", other),
        }
        let post_sha = if marker_path.exists() {
            Some(sha256_hex_of(&marker_path))
        } else {
            None
        };
        assert!(post_sha.is_none(), "H6: rejected governance decision must NOT write marker");
        out.push(ScenarioRecord {
            id,
            policy: "RequiredForLifecycleSensitive",
            context: "Supplied(GenesisBound,ActivateInitial,tampered)",
            expected_label: "GovernanceAuthorityRejected(InvalidIssuerSignature)",
            expected_match: r"Err\(GovernanceAuthorityRejected\(InvalidIssuerSignature",
            actual,
            marker_pre_sha: None,
            marker_post_sha: post_sha,
            marker_path,
            expect_no_mutation: true,
        });
    }

    // -----------------------------------------------------------------
    // H7 — gate-purity / non-MainNet-enabling smoke through
    //      `decide_v2_marker_acceptance_with_lifecycle_and_governance`.
    //      Two identical evaluations on the same inputs must return
    //      structurally-equal `Ok` decisions; the marker file must remain
    //      absent both times. Acceptance carries no MainNet-apply
    //      capability (the surface environment gate, unchanged by Run
    //      165, owns the MainNet refusal).
    // -----------------------------------------------------------------
    {
        let id = "H7_gate_pure_non_mainnet_enabling";
        let dir = out_dir.join("scenarios").join(id);
        fs::create_dir_all(&dir).expect("h7 dir");
        let marker_path = authority_state_file_path(&dir);
        let r = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None);
        let ratified = h.verify_v2(&r);
        let r1 = decide_v2_marker_acceptance_with_lifecycle_and_governance(
            make_inputs(&marker_path, &gh, &r, &ratified, AuthorityStateUpdateSource::StartupLoad),
            GovernanceProofPolicy::NotRequired,
            GovernanceProofContext::Unavailable,
        )
        .expect("h7 first eval");
        let r2 = decide_v2_marker_acceptance_with_lifecycle_and_governance(
            make_inputs(&marker_path, &gh, &r, &ratified, AuthorityStateUpdateSource::StartupLoad),
            GovernanceProofPolicy::NotRequired,
            GovernanceProofContext::Unavailable,
        )
        .expect("h7 second eval");
        // The decision is `pub` opaque; compare via accept-kind, candidate,
        // and persist intent (the three fields the surface caller relies on).
        assert_eq!(r1.kind(), r2.kind());
        assert_eq!(r1.candidate(), r2.candidate());
        assert_eq!(r1.should_persist(), r2.should_persist());
        assert!(!marker_path.exists(), "H7: pure gate must not write marker");
        let actual = format!("Ok({:?}) == Ok({:?})", r1.kind(), r2.kind());
        out.push(ScenarioRecord {
            id,
            policy: "NotRequired (x2 deterministic)",
            context: "Unavailable",
            expected_label: "Pure gate; deterministic accept; no MainNet apply enabled",
            expected_match: r"Ok\(FirstV2Write\) == Ok\(FirstV2Write\)",
            actual,
            marker_pre_sha: None,
            marker_post_sha: None,
            marker_path,
            expect_no_mutation: true,
        });
    }

    out
}

fn main() {
    let arg = env::args().nth(1).expect("usage: run_166_helper <OUT_DIR>");
    let out_dir = PathBuf::from(&arg);
    fs::create_dir_all(&out_dir).expect("create OUT_DIR");
    let records = run();

    // Per-scenario outputs.
    let mut manifest = String::new();
    let mut expected_outcomes = String::new();
    let mut actual_outcomes = String::new();
    for r in &records {
        let dir = out_dir.join("scenarios").join(r.id);
        fs::create_dir_all(&dir).expect("scenario dir");
        write_text(&dir.join("policy.txt"), r.policy);
        write_text(&dir.join("context.txt"), r.context);
        write_text(&dir.join("expected.txt"), r.expected_label);
        write_text(&dir.join("actual.txt"), &r.actual);
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
            // For seeded scenarios, pre/post SHA must match. For non-seeded
            // scenarios, post must be absent. Both invariants are asserted
            // inside `run()` already; we re-record them here as text.
            write_text(&dir.join("no_mutation_invariant.txt"), "asserted: pre==post (seeded) or post=ABSENT (unseeded)\n");
        }
        manifest.push_str(&format!("{}\t{}\t{}\n", r.id, r.expected_label, r.expected_match));
        expected_outcomes.push_str(&format!(
            "{}: policy={} context={} -> {}\n",
            r.id, r.policy, r.context, r.expected_label
        ));
        actual_outcomes.push_str(&format!("{}: {}\n", r.id, r.actual));
    }
    write_text(&out_dir.join("manifest.txt"), &manifest);
    write_text(&out_dir.join("expected_outcomes.txt"), &expected_outcomes);
    write_text(&out_dir.join("actual_outcomes.txt"), &actual_outcomes);

    println!(
        "[run-166-helper] OK — {} scenarios written under {}",
        records.len(),
        out_dir.display()
    );
}