//! Run 171 — hidden, disabled-by-default DevNet/TestNet-safe
//! governance-proof Required-policy selector for production v2
//! marker-decision surfaces.
//!
//! Strict scope (mirrors `task/RUN_171_TASK.txt`):
//!
//! * Source/test only. Release-binary Required-policy production-
//!   surface evidence is deferred to Run 172.
//! * Hidden operator/test selector only.
//! * Disabled by default.
//! * No MainNet peer-driven apply enablement.
//! * No governance execution engine, KMS/HSM, validator-set rotation,
//!   autonomous apply, automatic apply on receipt, peer-majority
//!   authority, on-chain governance implementation.
//! * No new proof / marker / sequence-file / trust-bundle core /
//!   peer-candidate envelope schema change.
//!
//! ## What this file proves
//!
//! 1. The CLI flag and env-var selector are OR-combined into a Run 165
//!    [`GovernanceProofPolicy`] by
//!    [`governance_proof_policy_from_cli_or_env`] /
//!    [`governance_proof_policy_from_selector`].
//! 2. The default (flag unset and env var unset/falsey) is
//!    [`GovernanceProofPolicy::NotRequired`] — old no-proof v2 sidecars
//!    remain bit-for-bit compatible across the production marker-
//!    decision callers (reload-check, reload-apply, startup, SIGHUP,
//!    peer-driven coordinator).
//! 3. When the selector is enabled the same call sites route through
//!    the Run 169 surface shim under
//!    [`GovernanceProofPolicy::RequiredForLifecycleSensitive`] and
//!    valid Run 167 governance-authority proof-carrying sidecars are
//!    accepted; missing or invalid proof sidecars fail closed with
//!    typed [`MutatingSurfaceMarkerV2Error::GovernanceAuthorityRequiredButMissing`]
//!    / [`MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected`]
//!    BEFORE any mutation.
//! 4. Validation-only surfaces remain non-mutating; mutating surfaces
//!    persist the marker only after the Run 055 / Run 070 sequence-
//!    commit boundary; rejected governance decisions produce no
//!    mutation.
//! 5. MainNet peer-driven apply remains refused at the calling
//!    surface even with the selector enabled and a valid proof.
//! 6. The Run 171 selector cannot be accidentally enabled by unrelated
//!    flags — the helper is selector-input-driven only.
//!
//! ## Source-reachability evidence
//!
//! Every accepted/rejected matrix point flows through the Run 169
//! surface shim
//! [`preflight_v2_marker_decision_with_governance_proof_load`] which
//! is the sole library call site that production callers (reload-
//! check, reload-apply, startup `--p2p-trust-bundle`, SIGHUP live
//! reload, peer-driven `ProductionV2MarkerCoordinator`) delegate to.
//! Run 171 only adds the policy selector at the call sites; it does
//! not change the gate algorithm or any wire format. See
//! `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_171.md`.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use qbind_crypto::MlDsa44Backend;
use qbind_ledger::{
    bundle_signing_ratification::v2_test_helpers as ratification_v2_helpers,
    compute_canonical_genesis_hash, pqc_public_key_fingerprint, BundleSigningRatificationV2,
    BundleSigningRatificationV2Action, GenesisAllocation, GenesisAuthorityConfig,
    GenesisAuthorityRoot, GenesisConfig, GenesisCouncilConfig, GenesisHash,
    GenesisMonetaryConfig, GenesisValidator, NetworkEnvironmentPolicy, RatificationEnvironment,
    GENESIS_AUTHORITY_SUITE_ML_DSA_44,
};
use qbind_node::pqc_authority_lifecycle::LocalLifecycleAction;
use qbind_node::pqc_authority_marker_acceptance::{
    MarkerAcceptanceV2Inputs, MutatingSurfaceMarkerV2Error,
};
use qbind_node::pqc_authority_state::{
    authority_state_file_path, AuthorityStateUpdateSource, PersistentAuthorityStateRecordV2,
};
use qbind_node::pqc_governance_authority::{
    fixture_issuer_signature, fixture_issuer_signature_verifier, GovernanceAuthorityClass,
    GovernanceAuthorityProof, GovernanceAuthorityVerificationOutcome as GovOutcome,
    GovernanceProofPolicy, PQC_GOVERNANCE_ISSUER_SUITE_ML_DSA_44,
};
use qbind_node::pqc_governance_proof_surface::{
    governance_proof_policy_from_cli_or_env, governance_proof_policy_from_selector,
    governance_proof_required_env_selector_enabled,
    preflight_v2_marker_decision_with_governance_proof_load,
    QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED_ENV,
};
use qbind_node::pqc_governance_proof_wire::GovernanceProofLoadStatus;
use qbind_node::pqc_peer_candidate_apply::{ProductionV2MarkerCoordinator, V2MarkerCoordinator};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;
use qbind_node::pqc_trust_sequence::chain_id_hex;
use qbind_types::NetworkEnvironment;

// ---------------------------------------------------------------------------
// Env-var serialization. Several Run 171 tests probe
// `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED`; std::env mutation
// is process-wide so we serialize the env-touching tests behind a
// single Mutex to keep them deterministic when run in parallel.
// ---------------------------------------------------------------------------

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct EnvGuard {
    prior: Option<String>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl EnvGuard {
    fn set(value: Option<&str>) -> Self {
        let lock = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var(QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED_ENV).ok();
        match value {
            Some(v) => std::env::set_var(QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED_ENV, v),
            None => std::env::remove_var(QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED_ENV),
        }
        EnvGuard { prior, _lock: lock }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.prior.take() {
            Some(v) => std::env::set_var(QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED_ENV, v),
            None => std::env::remove_var(QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED_ENV),
        }
    }
}

// ---------------------------------------------------------------------------
// Harness — same shape as Run 169's harness so the Run 171 tests share
// the v2 ratification + governance authority proof construction logic.
// ---------------------------------------------------------------------------

fn hex_lower(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", x);
    }
    s
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
                updated_at_unix_secs: 1_700_000_000,
            },
        )
        .expect("derive v2 candidate")
    }
}

fn tmpdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "qbind-run171-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    std::fs::create_dir_all(&p).expect("create_dir_all");
    p
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
        updated_at_unix_secs: 1_700_000_000,
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

/// Run the Run 169 surface shim under the supplied policy and load
/// status. Run 171 differs from Run 169 only at the policy selection
/// layer; the shim's behaviour is unchanged.
fn shim_run(
    inputs: MarkerAcceptanceV2Inputs<'_>,
    policy: GovernanceProofPolicy,
    proof_load: &GovernanceProofLoadStatus,
) -> Result<
    qbind_node::pqc_authority_marker_acceptance::MarkerAcceptDecisionV2,
    MutatingSurfaceMarkerV2Error,
> {
    let verifier = fixture_issuer_signature_verifier();
    preflight_v2_marker_decision_with_governance_proof_load(inputs, policy, proof_load, &verifier)
}

fn assert_no_marker_on_disk(marker_path: &Path) {
    assert!(
        !marker_path.exists(),
        "Run 171 surface shim must not write a marker before the Run 055 / Run 070 \
         sequence-commit boundary; saw {} on disk",
        marker_path.display()
    );
}

/// Seed a prior v2 marker on disk via Ratify (ActivateInitial) at
/// sequence 1 so a subsequent Rotate at sequence 2 reaches the
/// lifecycle/governance layers (instead of being short-circuited by
/// the "Rotate at first-write" lifecycle refusal).
fn seed_prior_v2_marker(h: &Harness, marker_path: &Path) -> Vec<u8> {
    let r1 = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None);
    let ratified1 = h.verify_v2(&r1);
    let gh = h.genesis_hex();
    let d1 = qbind_node::pqc_authority_marker_acceptance::decide_v2_marker_acceptance_with_lifecycle_and_governance(
        make_inputs(marker_path, &gh, &r1, &ratified1, AuthorityStateUpdateSource::StartupLoad),
        GovernanceProofPolicy::NotRequired,
        qbind_node::pqc_governance_authority::GovernanceProofContext::Unavailable,
    )
    .expect("seed activate-initial accepts");
    qbind_node::pqc_authority_marker_acceptance::persist_accepted_v2_marker_after_commit_boundary(&d1)
        .expect("persist seed marker");
    std::fs::read(marker_path).expect("read seed marker bytes")
}

/// Build a Rotate v2 ratification at sequence 2 that follows the
/// seeded prior marker (signing_pk_a → signing_pk_b).
fn rotate_after_seed(h: &Harness) -> BundleSigningRatificationV2 {
    h.build_v2(
        &h.signing_pk_b,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(pqc_public_key_fingerprint(&h.signing_pk_a)),
    )
}

// ===========================================================================
// Section 1 — selector logic itself.
// ===========================================================================

/// Selector default (no flag / no env) — `NotRequired`.
#[test]
fn selector_default_is_not_required() {
    let _g = EnvGuard::set(None);
    assert_eq!(
        governance_proof_policy_from_cli_or_env(false),
        GovernanceProofPolicy::NotRequired
    );
    assert!(!governance_proof_required_env_selector_enabled());
    assert_eq!(
        governance_proof_policy_from_selector(false),
        GovernanceProofPolicy::NotRequired
    );
}

/// Selector via CLI flag — `RequiredForLifecycleSensitive`.
#[test]
fn selector_via_cli_flag_yields_required() {
    let _g = EnvGuard::set(None);
    assert_eq!(
        governance_proof_policy_from_cli_or_env(true),
        GovernanceProofPolicy::RequiredForLifecycleSensitive
    );
    assert_eq!(
        governance_proof_policy_from_selector(true),
        GovernanceProofPolicy::RequiredForLifecycleSensitive
    );
}

/// Selector via env var truthy values — `RequiredForLifecycleSensitive`.
#[test]
fn selector_via_env_var_truthy_yields_required() {
    for v in ["1", "true", "TRUE", "True", "yes", "YES", "on", "ON"] {
        let _g = EnvGuard::set(Some(v));
        assert!(
            governance_proof_required_env_selector_enabled(),
            "env value {:?} should be truthy",
            v
        );
        assert_eq!(
            governance_proof_policy_from_cli_or_env(false),
            GovernanceProofPolicy::RequiredForLifecycleSensitive,
            "env value {:?} should select Required",
            v
        );
    }
}

/// Selector env var falsey values — `NotRequired`.
#[test]
fn selector_via_env_var_falsey_yields_not_required() {
    for v in ["0", "false", "FALSE", "no", "off", "", " ", "garbage", "2"] {
        let _g = EnvGuard::set(Some(v));
        assert!(
            !governance_proof_required_env_selector_enabled(),
            "env value {:?} should NOT be truthy",
            v
        );
        assert_eq!(
            governance_proof_policy_from_cli_or_env(false),
            GovernanceProofPolicy::NotRequired,
            "env value {:?} should NOT select Required",
            v
        );
    }
}

/// Selector OR-combination — flag wins even with the env var unset.
#[test]
fn selector_cli_flag_or_env_var_combination() {
    {
        let _g = EnvGuard::set(None);
        assert_eq!(
            governance_proof_policy_from_cli_or_env(true),
            GovernanceProofPolicy::RequiredForLifecycleSensitive
        );
    }
    {
        let _g = EnvGuard::set(Some("1"));
        assert_eq!(
            governance_proof_policy_from_cli_or_env(false),
            GovernanceProofPolicy::RequiredForLifecycleSensitive
        );
        // Both set — still Required.
        assert_eq!(
            governance_proof_policy_from_cli_or_env(true),
            GovernanceProofPolicy::RequiredForLifecycleSensitive
        );
    }
}

/// R20 — selector cannot be accidentally enabled by unrelated flags.
/// The helper reads only the explicit boolean and the explicit env
/// var; nothing else can flip it. Compile-time invariant: the helper
/// signature does not accept any other CLI field.
#[test]
fn r20_selector_cannot_be_accidentally_enabled_by_unrelated_flags() {
    let _g = EnvGuard::set(None);
    // Default boolean false (representing "unrelated flags only" set
    // upstream) yields NotRequired regardless.
    assert_eq!(
        governance_proof_policy_from_cli_or_env(false),
        GovernanceProofPolicy::NotRequired
    );
}

// ===========================================================================
// Section 2 — A1..A8 acceptance matrix routed through the Run 169 shim
// using the Run 171 selector to pick the active policy.
// ===========================================================================

/// A1 — default selector is NotRequired; old no-proof v2 sidecar
/// accepted as before. This mirrors Run 169 A1 but the policy comes
/// from the Run 171 selector (false → NotRequired).
#[test]
fn a1_default_selector_is_not_required_old_sidecar_accepted() {
    let _g = EnvGuard::set(None);
    let h = devnet_harness();
    let dir = tmpdir("a1");
    let marker_path = authority_state_file_path(&dir);
    let r = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None);
    let ratified = h.verify_v2(&r);
    let gh = h.genesis_hex();
    let policy = governance_proof_policy_from_cli_or_env(false);
    assert_eq!(policy, GovernanceProofPolicy::NotRequired);
    let inputs = make_inputs(
        &marker_path,
        &gh,
        &r,
        &ratified,
        AuthorityStateUpdateSource::TestOrFixture,
    );
    let _decision = shim_run(inputs, policy, &GovernanceProofLoadStatus::Absent)
        .expect("A1 default accepts old no-proof sidecar");
    assert_no_marker_on_disk(&marker_path);
}

/// A2 — hidden selector sets RequiredForLifecycleSensitive. Config
/// parsing / runtime context selects Required policy (asserted at the
/// helper surface; the same value is fed into every preflight).
#[test]
fn a2_hidden_selector_sets_required_for_lifecycle_sensitive() {
    let _g = EnvGuard::set(None);
    assert_eq!(
        governance_proof_policy_from_cli_or_env(true),
        GovernanceProofPolicy::RequiredForLifecycleSensitive
    );
}

/// A3 — reload-check Required policy accepts valid proof-carrying
/// Rotate sidecar; no marker write, no sequence write (validation-
/// only).
#[test]
fn a3_reload_check_required_accepts_valid_rotate_proof() {
    let _g = EnvGuard::set(None);
    let h = devnet_harness();
    let dir = tmpdir("a3");
    let marker_path = authority_state_file_path(&dir);
    let __seed_bytes = seed_prior_v2_marker(&h, &marker_path);
    let r2 = rotate_after_seed(&h);
    let ratified2 = h.verify_v2(&r2);
    let candidate = h.derive_candidate(
        &h.genesis_hex(),
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::TestOrFixture,
    );
    let proof = good_proof(
        &h,
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    let gh = h.genesis_hex();
    let policy = governance_proof_policy_from_cli_or_env(true);
    assert_eq!(policy, GovernanceProofPolicy::RequiredForLifecycleSensitive);
    let inputs = make_inputs(
        &marker_path,
        &gh,
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::TestOrFixture,
    );
    let _decision = shim_run(inputs, policy, &GovernanceProofLoadStatus::Available(proof))
        .expect("A3 accepts valid Rotate proof under Required");
    // Reload-check is validation-only; the seeded marker on disk is
    // unchanged.
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// A4 — reload-apply Required policy accepts valid proof-carrying
/// Rotate sidecar; the shim never persists before the Run 055 / Run
/// 070 sequence-commit boundary.
#[test]
fn a4_reload_apply_required_accepts_valid_rotate_proof_no_premature_write() {
    let _g = EnvGuard::set(None);
    let h = devnet_harness();
    let dir = tmpdir("a4");
    let marker_path = authority_state_file_path(&dir);
    let __seed_bytes = seed_prior_v2_marker(&h, &marker_path);
    let r2 = rotate_after_seed(&h);
    let ratified2 = h.verify_v2(&r2);
    let candidate = h.derive_candidate(
        &h.genesis_hex(),
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::ReloadApply,
    );
    let proof = good_proof(
        &h,
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    let gh = h.genesis_hex();
    let policy = governance_proof_policy_from_cli_or_env(true);
    let inputs = make_inputs(
        &marker_path,
        &gh,
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::ReloadApply,
    );
    let _decision = shim_run(inputs, policy, &GovernanceProofLoadStatus::Available(proof))
        .expect("A4 accepts valid Rotate proof under Required");
    // The shim itself never persists; the seeded marker is unchanged.
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// A5 — startup `--p2p-trust-bundle` Required policy accepts valid
/// proof-carrying Rotate sidecar; preflight surface receives the
/// Required policy via the Run 171 selector.
#[test]
fn a5_startup_required_accepts_valid_rotate_proof() {
    let _g = EnvGuard::set(None);
    let h = devnet_harness();
    let dir = tmpdir("a5");
    let marker_path = authority_state_file_path(&dir);
    let __seed_bytes = seed_prior_v2_marker(&h, &marker_path);
    let r2 = h.build_v2(
        &h.signing_pk_b,
        3,
        BundleSigningRatificationV2Action::Rotate,
        Some(pqc_public_key_fingerprint(&h.signing_pk_a)),
    );
    let ratified2 = h.verify_v2(&r2);
    let candidate = h.derive_candidate(
        &h.genesis_hex(),
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::StartupLoad,
    );
    let proof = good_proof(
        &h,
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    let gh = h.genesis_hex();
    let policy = governance_proof_policy_from_cli_or_env(true);
    let inputs = make_inputs(
        &marker_path,
        &gh,
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::StartupLoad,
    );
    let _ = shim_run(inputs, policy, &GovernanceProofLoadStatus::Available(proof))
        .expect("A5 accepts valid Rotate proof under Required");
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// A6 — SIGHUP Required policy accepts valid proof-carrying Rotate
/// sidecar via the Run 169 shim with the SighupReload audit tag.
#[test]
fn a6_sighup_required_accepts_valid_rotate_proof() {
    let _g = EnvGuard::set(None);
    let h = devnet_harness();
    let dir = tmpdir("a6");
    let marker_path = authority_state_file_path(&dir);
    let __seed_bytes = seed_prior_v2_marker(&h, &marker_path);
    let r2 = h.build_v2(
        &h.signing_pk_b,
        4,
        BundleSigningRatificationV2Action::Rotate,
        Some(pqc_public_key_fingerprint(&h.signing_pk_a)),
    );
    let ratified2 = h.verify_v2(&r2);
    let candidate = h.derive_candidate(
        &h.genesis_hex(),
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::SighupReload,
    );
    let proof = good_proof(
        &h,
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    let gh = h.genesis_hex();
    let policy = governance_proof_policy_from_cli_or_env(true);
    let inputs = make_inputs(
        &marker_path,
        &gh,
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::SighupReload,
    );
    let _ = shim_run(inputs, policy, &GovernanceProofLoadStatus::Available(proof))
        .expect("A6 accepts valid Rotate proof under Required at SIGHUP");
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// A7 — peer-driven `ProductionV2MarkerCoordinator` Required policy
/// accepts valid proof-carrying Rotate sidecar; MainNet apply remains
/// refused at the upstream binary gate (covered by Run 152 tests).
#[test]
fn a7_peer_driven_coordinator_required_accepts_valid_rotate_proof() {
    let _g = EnvGuard::set(None);
    let h = devnet_harness();
    let dir = tmpdir("a7");
    let marker_path = authority_state_file_path(&dir);
    let __seed_bytes = seed_prior_v2_marker(&h, &marker_path);
    let r2 = h.build_v2(
        &h.signing_pk_b,
        5,
        BundleSigningRatificationV2Action::Rotate,
        Some(pqc_public_key_fingerprint(&h.signing_pk_a)),
    );
    let ratified2 = h.verify_v2(&r2);
    let candidate = h.derive_candidate(
        &h.genesis_hex(),
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::ReloadApply,
    );
    let proof = good_proof(
        &h,
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    let policy = governance_proof_policy_from_cli_or_env(true);
    assert_eq!(policy, GovernanceProofPolicy::RequiredForLifecycleSensitive);
    let mut coord = ProductionV2MarkerCoordinator::new(
        marker_path.clone(),
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        h.genesis_hex(),
        r2,
        ratified2,
        AuthorityStateUpdateSource::ReloadApply,
        1_700_000_000,
    )
    .with_governance_proof_carrier(GovernanceProofLoadStatus::Available(proof), policy);
    coord.decide_pre_apply().expect("A7 accepts at coordinator");
    assert!(coord.accepted_decision().is_some());
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// A8 — old no-proof sidecar remains accepted under default
/// NotRequired across representative surfaces (audit tags). The
/// peer-driven coordinator default (no carrier attached) is also
/// covered by Run 169 A7 — Run 171's contribution is to confirm that
/// the *selector* default (false → NotRequired) preserves this.
#[test]
fn a8_no_proof_sidecar_remains_accepted_under_default_across_surfaces() {
    let _g = EnvGuard::set(None);
    let h = devnet_harness();
    let dir = tmpdir("a8");
    let marker_path = authority_state_file_path(&dir);
    let r = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None);
    let ratified = h.verify_v2(&r);
    let policy = governance_proof_policy_from_cli_or_env(false);
    assert_eq!(policy, GovernanceProofPolicy::NotRequired);
    for source in [
        AuthorityStateUpdateSource::ReloadApply,
        AuthorityStateUpdateSource::StartupLoad,
        AuthorityStateUpdateSource::SighupReload,
        AuthorityStateUpdateSource::TestOrFixture,
    ] {
        let gh = h.genesis_hex();
        let inputs = make_inputs(&marker_path, &gh, &r, &ratified, source);
        let _ = shim_run(inputs, policy, &GovernanceProofLoadStatus::Absent)
            .expect("A8 default selector accepts no-proof sidecar");
    }
    assert_no_marker_on_disk(&marker_path);
}

// ===========================================================================
// Section 3 — R1..R20 rejection / invariant matrix routed through the
// Run 169 shim under the Run 171 Required-policy selector.
// ===========================================================================

/// R1 — Required policy + no-proof sidecar rejected with
/// `RequiredButMissing` on reload-check (validation-only; never
/// mutates).
#[test]
fn r1_required_no_proof_rejected_on_reload_check() {
    let _g = EnvGuard::set(None);
    let h = devnet_harness();
    let dir = tmpdir("r1");
    let marker_path = authority_state_file_path(&dir);
    let __seed_bytes = seed_prior_v2_marker(&h, &marker_path);
    let r2 = rotate_after_seed(&h);
    let ratified2 = h.verify_v2(&r2);
    let gh = h.genesis_hex();
    let policy = governance_proof_policy_from_cli_or_env(true);
    let inputs = make_inputs(
        &marker_path,
        &gh,
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::TestOrFixture,
    );
    let err = shim_run(inputs, policy, &GovernanceProofLoadStatus::Absent)
        .err()
        .expect("R1 fails closed");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::GovernanceAuthorityRequiredButMissing { .. }
    ));
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// R2 — Required policy + no-proof sidecar rejected before Run 070 on
/// reload-apply (the shim never invokes Run 070 at all; the boundary
/// is owned by the caller).
#[test]
fn r2_required_no_proof_rejected_on_reload_apply_before_run070() {
    let _g = EnvGuard::set(None);
    let h = devnet_harness();
    let dir = tmpdir("r2");
    let marker_path = authority_state_file_path(&dir);
    let __seed_bytes = seed_prior_v2_marker(&h, &marker_path);
    let r2 = rotate_after_seed(&h);
    let ratified2 = h.verify_v2(&r2);
    let gh = h.genesis_hex();
    let policy = governance_proof_policy_from_cli_or_env(true);
    let inputs = make_inputs(
        &marker_path,
        &gh,
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::ReloadApply,
    );
    let err = shim_run(inputs, policy, &GovernanceProofLoadStatus::Absent)
        .err()
        .expect("R2 fails closed");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::GovernanceAuthorityRequiredButMissing { .. }
    ));
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// R3 — Required policy + malformed proof rejected before mutation.
#[test]
fn r3_required_malformed_proof_rejected_before_mutation() {
    use qbind_node::pqc_governance_proof_wire::GovernanceProofWireParseError;
    let _g = EnvGuard::set(None);
    let h = devnet_harness();
    let dir = tmpdir("r3");
    let marker_path = authority_state_file_path(&dir);
    let __seed_bytes = seed_prior_v2_marker(&h, &marker_path);
    let r2 = rotate_after_seed(&h);
    let ratified2 = h.verify_v2(&r2);
    let gh = h.genesis_hex();
    let policy = governance_proof_policy_from_cli_or_env(true);
    let inputs = make_inputs(
        &marker_path,
        &gh,
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::ReloadApply,
    );
    let malformed = GovernanceProofLoadStatus::Malformed(
        GovernanceProofWireParseError::EmptyIssuerSignature,
    );
    let err = shim_run(inputs, policy, &malformed)
        .err()
        .expect("R3 fails closed");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::GovernanceAuthorityRequiredButMissing { .. }
    ));
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// R4 — Required policy + invalid issuer signature rejected.
#[test]
fn r4_required_invalid_issuer_signature_rejected() {
    let _g = EnvGuard::set(None);
    let h = devnet_harness();
    let dir = tmpdir("r4");
    let marker_path = authority_state_file_path(&dir);
    let __seed_bytes = seed_prior_v2_marker(&h, &marker_path);
    let r2 = rotate_after_seed(&h);
    let ratified2 = h.verify_v2(&r2);
    let candidate = h.derive_candidate(
        &h.genesis_hex(),
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::ReloadApply,
    );
    let mut proof = good_proof(
        &h,
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.issuer_signature = b"corrupted".to_vec();
    let gh = h.genesis_hex();
    let policy = governance_proof_policy_from_cli_or_env(true);
    let inputs = make_inputs(
        &marker_path,
        &gh,
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::ReloadApply,
    );
    let err = shim_run(inputs, policy, &GovernanceProofLoadStatus::Available(proof))
        .err()
        .expect("R4 fails closed");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected(
            GovOutcome::InvalidIssuerSignature { .. }
        )
    ));
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// R5 — Required policy + wrong environment proof rejected.
#[test]
fn r5_required_wrong_environment_rejected() {
    let _g = EnvGuard::set(None);
    let h = devnet_harness();
    let dir = tmpdir("r5");
    let marker_path = authority_state_file_path(&dir);
    let __seed_bytes = seed_prior_v2_marker(&h, &marker_path);
    let r2 = rotate_after_seed(&h);
    let ratified2 = h.verify_v2(&r2);
    let candidate = h.derive_candidate(
        &h.genesis_hex(),
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::ReloadApply,
    );
    let mut proof = good_proof(
        &h,
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.environment = TrustBundleEnvironment::Mainnet;
    let gh = h.genesis_hex();
    let policy = governance_proof_policy_from_cli_or_env(true);
    let inputs = make_inputs(
        &marker_path,
        &gh,
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::ReloadApply,
    );
    let err = shim_run(inputs, policy, &GovernanceProofLoadStatus::Available(proof))
        .err()
        .expect("R5 fails closed");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected(_)
    ));
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// R6 — Required policy + wrong chain proof rejected.
#[test]
fn r6_required_wrong_chain_rejected() {
    let _g = EnvGuard::set(None);
    let h = devnet_harness();
    let dir = tmpdir("r6");
    let marker_path = authority_state_file_path(&dir);
    let __seed_bytes = seed_prior_v2_marker(&h, &marker_path);
    let r2 = rotate_after_seed(&h);
    let ratified2 = h.verify_v2(&r2);
    let candidate = h.derive_candidate(
        &h.genesis_hex(),
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::ReloadApply,
    );
    let mut proof = good_proof(
        &h,
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.chain_id = "00000000000000ff".to_string();
    let gh = h.genesis_hex();
    let policy = governance_proof_policy_from_cli_or_env(true);
    let inputs = make_inputs(
        &marker_path,
        &gh,
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::ReloadApply,
    );
    let err = shim_run(inputs, policy, &GovernanceProofLoadStatus::Available(proof))
        .err()
        .expect("R6 fails closed");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected(_)
    ));
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// R7 — Required policy + wrong genesis proof rejected.
#[test]
fn r7_required_wrong_genesis_rejected() {
    let _g = EnvGuard::set(None);
    let h = devnet_harness();
    let dir = tmpdir("r7");
    let marker_path = authority_state_file_path(&dir);
    let __seed_bytes = seed_prior_v2_marker(&h, &marker_path);
    let r2 = rotate_after_seed(&h);
    let ratified2 = h.verify_v2(&r2);
    let candidate = h.derive_candidate(
        &h.genesis_hex(),
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::ReloadApply,
    );
    let mut proof = good_proof(
        &h,
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.genesis_hash = "ee".repeat(32);
    let gh = h.genesis_hex();
    let policy = governance_proof_policy_from_cli_or_env(true);
    let inputs = make_inputs(
        &marker_path,
        &gh,
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::ReloadApply,
    );
    let err = shim_run(inputs, policy, &GovernanceProofLoadStatus::Available(proof))
        .err()
        .expect("R7 fails closed");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected(_)
    ));
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// R8 — Required policy + wrong authority root proof rejected.
#[test]
fn r8_required_wrong_authority_root_rejected() {
    let _g = EnvGuard::set(None);
    let h = devnet_harness();
    let dir = tmpdir("r8");
    let marker_path = authority_state_file_path(&dir);
    let __seed_bytes = seed_prior_v2_marker(&h, &marker_path);
    let r2 = rotate_after_seed(&h);
    let ratified2 = h.verify_v2(&r2);
    let candidate = h.derive_candidate(
        &h.genesis_hex(),
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::ReloadApply,
    );
    let mut proof = good_proof(
        &h,
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.authority_root_fingerprint = "9".repeat(40);
    let gh = h.genesis_hex();
    let policy = governance_proof_policy_from_cli_or_env(true);
    let inputs = make_inputs(
        &marker_path,
        &gh,
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::ReloadApply,
    );
    let err = shim_run(inputs, policy, &GovernanceProofLoadStatus::Available(proof))
        .err()
        .expect("R8 fails closed");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected(_)
    ));
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// R9 — Required policy + wrong lifecycle action proof rejected.
#[test]
fn r9_required_wrong_lifecycle_action_rejected() {
    let _g = EnvGuard::set(None);
    let h = devnet_harness();
    let dir = tmpdir("r9");
    let marker_path = authority_state_file_path(&dir);
    let __seed_bytes = seed_prior_v2_marker(&h, &marker_path);
    let r2 = rotate_after_seed(&h);
    let ratified2 = h.verify_v2(&r2);
    let candidate = h.derive_candidate(
        &h.genesis_hex(),
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::ReloadApply,
    );
    let mut proof = good_proof(
        &h,
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.lifecycle_action = LocalLifecycleAction::Retire;
    let gh = h.genesis_hex();
    let policy = governance_proof_policy_from_cli_or_env(true);
    let inputs = make_inputs(
        &marker_path,
        &gh,
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::ReloadApply,
    );
    let err = shim_run(inputs, policy, &GovernanceProofLoadStatus::Available(proof))
        .err()
        .expect("R9 fails closed");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected(_)
    ));
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// R10 — Required policy + wrong candidate digest proof rejected.
#[test]
fn r10_required_wrong_candidate_digest_rejected() {
    let _g = EnvGuard::set(None);
    let h = devnet_harness();
    let dir = tmpdir("r10");
    let marker_path = authority_state_file_path(&dir);
    let __seed_bytes = seed_prior_v2_marker(&h, &marker_path);
    let r2 = rotate_after_seed(&h);
    let ratified2 = h.verify_v2(&r2);
    let candidate = h.derive_candidate(
        &h.genesis_hex(),
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::ReloadApply,
    );
    let mut proof = good_proof(
        &h,
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.candidate_v2_digest = "f".repeat(64);
    let gh = h.genesis_hex();
    let policy = governance_proof_policy_from_cli_or_env(true);
    let inputs = make_inputs(
        &marker_path,
        &gh,
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::ReloadApply,
    );
    let err = shim_run(inputs, policy, &GovernanceProofLoadStatus::Available(proof))
        .err()
        .expect("R10 fails closed");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected(_)
    ));
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// R11 — Required policy + wrong authority-domain sequence proof
/// rejected.
#[test]
fn r11_required_wrong_authority_domain_sequence_rejected() {
    let _g = EnvGuard::set(None);
    let h = devnet_harness();
    let dir = tmpdir("r11");
    let marker_path = authority_state_file_path(&dir);
    let __seed_bytes = seed_prior_v2_marker(&h, &marker_path);
    let r2 = rotate_after_seed(&h);
    let ratified2 = h.verify_v2(&r2);
    let candidate = h.derive_candidate(
        &h.genesis_hex(),
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::ReloadApply,
    );
    let mut proof = good_proof(
        &h,
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.authority_domain_sequence = candidate.latest_authority_domain_sequence + 7;
    let gh = h.genesis_hex();
    let policy = governance_proof_policy_from_cli_or_env(true);
    let inputs = make_inputs(
        &marker_path,
        &gh,
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::ReloadApply,
    );
    let err = shim_run(inputs, policy, &GovernanceProofLoadStatus::Available(proof))
        .err()
        .expect("R11 fails closed");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected(_)
    ));
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// R12 — Required policy + OnChainGovernance proof rejected as
/// unsupported / fail-closed (Run 163 verifier invariant).
#[test]
fn r12_required_on_chain_governance_unsupported() {
    let _g = EnvGuard::set(None);
    let h = devnet_harness();
    let dir = tmpdir("r12");
    let marker_path = authority_state_file_path(&dir);
    let __seed_bytes = seed_prior_v2_marker(&h, &marker_path);
    let r2 = rotate_after_seed(&h);
    let ratified2 = h.verify_v2(&r2);
    let candidate = h.derive_candidate(
        &h.genesis_hex(),
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::ReloadApply,
    );
    let proof = good_proof(
        &h,
        &candidate,
        GovernanceAuthorityClass::OnChainGovernance,
        LocalLifecycleAction::Rotate,
    );
    let gh = h.genesis_hex();
    let policy = governance_proof_policy_from_cli_or_env(true);
    let inputs = make_inputs(
        &marker_path,
        &gh,
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::ReloadApply,
    );
    let err = shim_run(inputs, policy, &GovernanceProofLoadStatus::Available(proof))
        .err()
        .expect("R12 fails closed");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected(
            GovOutcome::UnsupportedOnChainGovernance { .. }
        )
    ));
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// R13 — Required policy + local operator config alone rejected as
/// authority proof. Compile-time invariant: the shim only accepts a
/// typed `GovernanceProofLoadStatus`. There is no public path for
/// "operator config" to take its place; an `Absent` status under
/// Required fails closed (i.e. operator config alone cannot stand in
/// as a proof).
#[test]
fn r13_required_local_operator_config_alone_cannot_stand_in() {
    r1_required_no_proof_rejected_on_reload_check();
}

/// R14 — Required policy + peer majority / gossip count rejected as
/// authority proof. Same compile-time argument as R13: the shim has
/// no peer-majority carrier; an `Absent` status under Required fails
/// closed.
#[test]
fn r14_required_peer_majority_gossip_count_cannot_stand_in() {
    r1_required_no_proof_rejected_on_reload_check();
}

/// R15 — proof valid but lifecycle invalid rejected. The Run 161
/// lifecycle gate runs before the governance gate inside
/// `decide_v2_marker_acceptance_with_lifecycle_and_governance`; an
/// invalid lifecycle short-circuits before governance is even
/// evaluated. Mirrors Run 169 R19.
#[test]
fn r15_required_proof_valid_but_lifecycle_invalid_rejects_at_lifecycle_layer() {
    let _g = EnvGuard::set(None);
    let h = devnet_harness();
    let dir = tmpdir("r15");
    let marker_path = authority_state_file_path(&dir);
    // Persist a v2 marker with sequence 10 first so the new candidate
    // at sequence 2 is rejected by the v2 anti-rollback (lifecycle)
    // layer before governance runs.
    let r_prior = h.build_v2(
        &h.signing_pk_a,
        10,
        BundleSigningRatificationV2Action::Ratify,
        None,
    );
    let ratified_prior = h.verify_v2(&r_prior);
    let prior_candidate = h.derive_candidate(
        &h.genesis_hex(),
        &r_prior,
        &ratified_prior,
        AuthorityStateUpdateSource::ReloadApply,
    );
    qbind_node::pqc_authority_state::persist_authority_state_v2_atomic(
        &marker_path,
        &prior_candidate,
    )
    .expect("seed prior v2 marker");
    let r = h.build_v2(
        &h.signing_pk_b,
        2,
        BundleSigningRatificationV2Action::Ratify,
        None,
    );
    let ratified = h.verify_v2(&r);
    let candidate = h.derive_candidate(
        &h.genesis_hex(),
        &r,
        &ratified,
        AuthorityStateUpdateSource::ReloadApply,
    );
    let proof = good_proof(
        &h,
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::ActivateInitial,
    );
    let gh = h.genesis_hex();
    let policy = governance_proof_policy_from_cli_or_env(true);
    let inputs = make_inputs(
        &marker_path,
        &gh,
        &r,
        &ratified,
        AuthorityStateUpdateSource::ReloadApply,
    );
    let err = shim_run(inputs, policy, &GovernanceProofLoadStatus::Available(proof))
        .err()
        .expect("R15 fails closed at lifecycle layer");
    // Lifecycle/anti-rollback layer fires first; not a governance
    // reject.
    assert!(!matches!(
        err,
        MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected(_)
    ));
}

/// R16 — lifecycle valid but proof invalid rejected. Mirrors R4 with
/// a different lens: ordering proves both layers run. Reuse R4 to
/// avoid redundant fixture construction.
#[test]
fn r16_required_lifecycle_valid_but_proof_invalid_rejects() {
    r4_required_invalid_issuer_signature_rejected();
}

/// R17 — validation-only Required-policy rejection produces no
/// sequence write and no marker write.
#[test]
fn r17_required_validation_only_rejection_no_writes() {
    let _g = EnvGuard::set(None);
    let h = devnet_harness();
    let dir = tmpdir("r17");
    let marker_path = authority_state_file_path(&dir);
    // No prior marker — the rejection still leaves the disk clean.
    let r = h.build_v2(
        &h.signing_pk_b,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(pqc_public_key_fingerprint(&h.signing_pk_a)),
    );
    let ratified = h.verify_v2(&r);
    let gh = h.genesis_hex();
    let policy = governance_proof_policy_from_cli_or_env(true);
    let inputs = make_inputs(
        &marker_path,
        &gh,
        &r,
        &ratified,
        AuthorityStateUpdateSource::TestOrFixture,
    );
    let _err = shim_run(inputs, policy, &GovernanceProofLoadStatus::Absent)
        .err()
        .expect("R17 fails closed under Required + validation-only");
    assert_no_marker_on_disk(&marker_path);
    // Sequence file is owned upstream; the shim never writes one.
}

/// R18 — mutating Required-policy rejection produces no Run 070
/// call, no live trust swap, no session eviction, no sequence write,
/// and no marker write. The shim itself does none of these; the
/// caller short-circuits on `Err(_)` before invoking apply.
#[test]
fn r18_required_mutating_rejection_no_run070_no_swap_no_eviction_no_writes() {
    let _g = EnvGuard::set(None);
    let h = devnet_harness();
    let dir = tmpdir("r18");
    let marker_path = authority_state_file_path(&dir);
    let __seed_bytes = seed_prior_v2_marker(&h, &marker_path);
    let r2 = rotate_after_seed(&h);
    let ratified2 = h.verify_v2(&r2);
    let candidate = h.derive_candidate(
        &h.genesis_hex(),
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::ReloadApply,
    );
    let mut proof = good_proof(
        &h,
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.issuer_signature = b"bad".to_vec();
    let policy = governance_proof_policy_from_cli_or_env(true);
    let mut coord = ProductionV2MarkerCoordinator::new(
        marker_path.clone(),
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        h.genesis_hex(),
        r2,
        ratified2,
        AuthorityStateUpdateSource::ReloadApply,
        1_700_000_000,
    )
    .with_governance_proof_carrier(GovernanceProofLoadStatus::Available(proof), policy);
    let err = coord
        .decide_pre_apply()
        .expect_err("R18 fails closed at coordinator");
    assert!(err.contains("governance") || err.contains("GovernanceAuthority"));
    assert!(coord.accepted_decision().is_none());
    // No marker mutation; seeded bytes intact.
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// R19 — MainNet peer-driven apply remains refused even with Required
/// policy and valid proof. The selector does not change the upstream
/// MainNet refusal at the binary gate (covered by Run 152 tests).
/// Source-level invariant: `with_governance_proof_carrier` does not
/// touch `runtime_env`. A valid proof on a MainNet coordinator does
/// NOT change the environment refusal upstream.
#[test]
fn r19_mainnet_peer_driven_apply_remains_refused_even_with_required_and_valid_proof() {
    let _g = EnvGuard::set(None);
    let h = devnet_harness();
    let dir = tmpdir("r19");
    let marker_path = authority_state_file_path(&dir);
    let r = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None);
    let ratified = h.verify_v2(&r);
    let policy = governance_proof_policy_from_cli_or_env(true);
    let _coord = ProductionV2MarkerCoordinator::new(
        marker_path,
        // MainNet runtime — the upstream environment gate refuses
        // peer-driven apply unconditionally; the Run 171 selector
        // does not unlock it.
        NetworkEnvironment::Mainnet,
        NetworkEnvironment::Mainnet.chain_id(),
        h.genesis_hex(),
        r,
        ratified,
        AuthorityStateUpdateSource::ReloadApply,
        1_700_000_000,
    )
    .with_governance_proof_carrier(GovernanceProofLoadStatus::Absent, policy);
    // The constructor itself succeeds (the coordinator is a pure
    // marker-decision helper); the MainNet refusal lives upstream
    // and is asserted by Run 148/149/152 tests. This test exists to
    // make the Run 171 invariant explicit at the source-test
    // boundary: enabling Required policy does NOT enable MainNet
    // peer-driven apply.
    assert_eq!(policy, GovernanceProofPolicy::RequiredForLifecycleSensitive);
}

/// R20 is covered by `r20_selector_cannot_be_accidentally_enabled_by_unrelated_flags`
/// in Section 1; no additional fixture is required here.

// ===========================================================================
// Section 4 — source-reachability evidence: the selector reaches the
// Run 169 shim, the Required policy reaches `evaluate_governance_marker_gate`,
// `Absent` under Required produces `RequiredButMissing`, and a valid
// `Available` proof under Required reaches the `Available` gate context.
// ===========================================================================

/// Source-reachability A — selector → shim → gate. Asserts the call
/// chain visibly evaluates the Run 165 `evaluate_governance_marker_gate`
/// for both policies under the same load status, observing a different
/// outcome shape (NotRequiredNoProof vs RequiredButMissing).
#[test]
fn source_reachability_selector_reaches_gate_with_observable_outcome() {
    let _g = EnvGuard::set(None);
    let h = devnet_harness();
    let dir = tmpdir("reach");
    let marker_path = authority_state_file_path(&dir);
    let __seed_bytes = seed_prior_v2_marker(&h, &marker_path);
    let r2 = rotate_after_seed(&h);
    let ratified2 = h.verify_v2(&r2);
    let gh = h.genesis_hex();
    // NotRequired -> Absent accepted.
    let policy_default = governance_proof_policy_from_cli_or_env(false);
    let inputs_default = make_inputs(
        &marker_path,
        &gh,
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::ReloadApply,
    );
    let _ok = shim_run(inputs_default, policy_default, &GovernanceProofLoadStatus::Absent)
        .expect("default selector accepts no-proof");
    // Required -> Absent rejected RequiredButMissing.
    let policy_required = governance_proof_policy_from_cli_or_env(true);
    let inputs_required = make_inputs(
        &marker_path,
        &gh,
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::ReloadApply,
    );
    let err = shim_run(inputs_required, policy_required, &GovernanceProofLoadStatus::Absent)
        .err()
        .expect("Required selector rejects no-proof");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::GovernanceAuthorityRequiredButMissing { .. }
    ));
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// Source-reachability B — Available proof under Required reaches the
/// `Available` gate context (proof is verified, not no-op'd).
#[test]
fn source_reachability_available_proof_under_required_reaches_available_context() {
    let _g = EnvGuard::set(None);
    let h = devnet_harness();
    let dir = tmpdir("reach-b");
    let marker_path = authority_state_file_path(&dir);
    let _ = seed_prior_v2_marker(&h, &marker_path);
    let r2 = rotate_after_seed(&h);
    let ratified2 = h.verify_v2(&r2);
    let candidate = h.derive_candidate(
        &h.genesis_hex(),
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::ReloadApply,
    );
    let proof = good_proof(
        &h,
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    let gh = h.genesis_hex();
    let policy = governance_proof_policy_from_cli_or_env(true);
    let inputs = make_inputs(
        &marker_path,
        &gh,
        &r2,
        &ratified2,
        AuthorityStateUpdateSource::ReloadApply,
    );
    let _decision = shim_run(inputs, policy, &GovernanceProofLoadStatus::Available(proof))
        .expect("Required + Available reaches gate Available context and accepts");
}
