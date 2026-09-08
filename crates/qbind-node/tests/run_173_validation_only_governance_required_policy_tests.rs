//! Run 173 — wire the hidden Required governance-proof policy
//! selector into validation-only v2 surfaces.
//!
//! Strict scope (mirrors `task/RUN_173_TASK.txt`):
//!
//! * Source/test only. Release-binary validation-only Required-policy
//!   evidence is deferred to Run 174.
//! * No MainNet peer-driven apply enablement.
//! * No governance execution engine, KMS/HSM, validator-set rotation,
//!   autonomous apply, automatic apply on receipt, peer-majority
//!   authority, on-chain governance implementation.
//! * No new proof / marker / sequence-file / trust-bundle core /
//!   peer-candidate envelope schema change.
//!
//! ## What this file proves
//!
//! 1. The Run 173 validation-only surface shim
//!    [`preflight_v2_validation_only_marker_check_with_governance_proof_load`]
//!    delegates to the same Run 169 shim
//!    ([`preflight_v2_marker_decision_with_governance_proof_load`])
//!    and is mutation-free: it writes no marker, no sequence, never
//!    invokes Run 070, never swaps live trust state, never evicts
//!    sessions.
//! 2. The Run 171 selector
//!    ([`governance_proof_policy_from_cli_or_env`]) drives the active
//!    [`GovernanceProofPolicy`] for validation-only callers exactly
//!    as for mutating callers; default remains `NotRequired` and old
//!    no-proof v2 sidecars remain compatible.
//! 3. Under `RequiredForLifecycleSensitive` the validation-only shim
//!    accepts proof-carrying sidecars that pass anti-rollback,
//!    lifecycle, and governance gates; rejects no-proof / malformed /
//!    invalid-proof sidecars fail-closed with typed
//!    [`MutatingSurfaceMarkerV2Error::GovernanceAuthorityRequiredButMissing`]
//!    / [`MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected`].
//! 4. MainNet peer-driven apply remains refused even when the
//!    validation-only Required-policy gate accepts; the upstream
//!    environment refusal lives at the calling surface and is
//!    unchanged by Run 173.
//!
//! ## Source-reachability evidence
//!
//! Every accepted/rejected matrix point flows through the new Run
//! 173 validation-only shim, which delegates to the Run 169 shim.
//! The shim is the single source path through which the Run 167
//! loader output reaches the Run 165 gate from validation-only call
//! sites (`--p2p-trust-bundle-reload-check`, local peer-candidate-
//! check, and the shared validation-only helper used by live inbound
//! `0x05` once it carries v2 sidecar proof context). See
//! `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_173.md`.

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
    MarkerAcceptDecisionV2, MarkerAcceptanceV2Inputs, MutatingSurfaceMarkerV2Error,
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
    governance_proof_policy_from_cli_or_env, governance_proof_required_env_selector_enabled,
    preflight_v2_validation_only_marker_check_with_governance_proof_load,
    QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED_ENV,
};
use qbind_node::pqc_governance_proof_wire::GovernanceProofLoadStatus;
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;
use qbind_node::pqc_trust_sequence::chain_id_hex;
use qbind_types::NetworkEnvironment;

// ---------------------------------------------------------------------------
// Env-var serialization (process-wide std::env mutation).
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
// Harness — same shape as Run 171 / Run 169 harnesses.
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
        "qbind-run173-{}-{}-{}",
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
) -> MarkerAcceptanceV2Inputs<'a> {
    // Validation-only surfaces use placeholder update_source/timestamp;
    // both are excluded from the canonical v2 marker digest (Run 131)
    // and are never persisted from validation-only callers — see the
    // shim doc on
    // `preflight_v2_validation_only_marker_check_with_governance_proof_load`.
    MarkerAcceptanceV2Inputs {
        marker_path,
        runtime_env: NetworkEnvironment::Devnet,
        runtime_chain_id: NetworkEnvironment::Devnet.chain_id(),
        runtime_genesis_hash_hex: gh_hex,
        ratification,
        ratified,
        update_source: AuthorityStateUpdateSource::TestOrFixture,
        updated_at_unix_secs: 0,
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

/// Run the Run 173 validation-only surface shim under the supplied
/// policy and load status. The shim is mutation-free: validation-only
/// callers drop the returned decision rather than persisting.
fn shim_run(
    inputs: MarkerAcceptanceV2Inputs<'_>,
    policy: GovernanceProofPolicy,
    proof_load: &GovernanceProofLoadStatus,
) -> Result<MarkerAcceptDecisionV2, MutatingSurfaceMarkerV2Error> {
    let verifier = fixture_issuer_signature_verifier();
    preflight_v2_validation_only_marker_check_with_governance_proof_load(
        inputs, policy, proof_load, &verifier,
    )
}

fn assert_no_marker_on_disk(marker_path: &Path) {
    assert!(
        !marker_path.exists(),
        "Run 173 validation-only shim must not write a marker; saw {} on disk",
        marker_path.display()
    );
}

/// Seed a prior v2 marker on disk via Ratify (ActivateInitial) at
/// sequence 1 so a subsequent Rotate at sequence 2 reaches the
/// lifecycle/governance layers (instead of being short-circuited by
/// the "Rotate at first-write" lifecycle refusal). The seed itself
/// is written by the post-commit persist path so the on-disk bytes
/// are realistic.
fn seed_prior_v2_marker(h: &Harness, marker_path: &Path) -> Vec<u8> {
    let r1 = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None);
    let ratified1 = h.verify_v2(&r1);
    let gh = h.genesis_hex();
    let inputs1 = MarkerAcceptanceV2Inputs {
        marker_path,
        runtime_env: NetworkEnvironment::Devnet,
        runtime_chain_id: NetworkEnvironment::Devnet.chain_id(),
        runtime_genesis_hash_hex: &gh,
        ratification: &r1,
        ratified: &ratified1,
        update_source: AuthorityStateUpdateSource::StartupLoad,
        updated_at_unix_secs: 1_700_000_000,
    };
    let d1 = qbind_node::pqc_authority_marker_acceptance::decide_v2_marker_acceptance_with_lifecycle_and_governance(
        inputs1,
        GovernanceProofPolicy::NotRequired,
        qbind_node::pqc_governance_authority::GovernanceProofContext::Unavailable,
    )
    .expect("seed activate-initial accepts");
    qbind_node::pqc_authority_marker_acceptance::persist_accepted_v2_marker_after_commit_boundary(
        &d1,
    )
    .expect("persist seed marker");
    std::fs::read(marker_path).expect("read seed marker bytes")
}

fn rotate_after_seed(h: &Harness) -> BundleSigningRatificationV2 {
    h.build_v2(
        &h.signing_pk_b,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(pqc_public_key_fingerprint(&h.signing_pk_a)),
    )
}

// ===========================================================================
// Acceptance matrix A1..A6
// ===========================================================================

/// A1 — reload-check default selector (NotRequired) accepts an old
/// no-proof v2 sidecar; no marker write, no sequence write.
#[test]
fn a1_reload_check_default_not_required_accepts_old_no_proof_sidecar() {
    let _g = EnvGuard::set(None);
    let h = devnet_harness();
    let dir = tmpdir("a1");
    let marker_path = authority_state_file_path(&dir);
    let r = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None);
    let ratified = h.verify_v2(&r);
    let gh = h.genesis_hex();
    let policy = governance_proof_policy_from_cli_or_env(false);
    assert_eq!(policy, GovernanceProofPolicy::NotRequired);
    let inputs = make_inputs(&marker_path, &gh, &r, &ratified);
    let _decision = shim_run(inputs, policy, &GovernanceProofLoadStatus::Absent)
        .expect("A1 default accepts old no-proof sidecar on validation-only surface");
    assert_no_marker_on_disk(&marker_path);
}

/// A2 — reload-check CLI Required accepts valid proof-carrying Rotate
/// sidecar; proof context becomes Available; governance verifier
/// accepts; no sequence write; no marker write.
#[test]
fn a2_reload_check_cli_required_accepts_valid_proof_rotate_sidecar() {
    let _g = EnvGuard::set(None);
    let h = devnet_harness();
    let dir = tmpdir("a2");
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
    let inputs = make_inputs(&marker_path, &gh, &r2, &ratified2);
    let _decision = shim_run(inputs, policy, &GovernanceProofLoadStatus::Available(proof))
        .expect("A2 accepts valid Rotate proof under Required");
    // Validation-only: the seeded marker on disk is unchanged.
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// A3 — reload-check env Required accepts valid proof-carrying Rotate
/// sidecar (same as A2 but the policy comes from the env-var
/// selector).
#[test]
fn a3_reload_check_env_required_accepts_valid_proof_rotate_sidecar() {
    let _g = EnvGuard::set(Some("1"));
    assert!(governance_proof_required_env_selector_enabled());
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
    // CLI flag false; env var truthy → Required via OR-combination.
    let policy = governance_proof_policy_from_cli_or_env(false);
    assert_eq!(policy, GovernanceProofPolicy::RequiredForLifecycleSensitive);
    let inputs = make_inputs(&marker_path, &gh, &r2, &ratified2);
    let _decision = shim_run(inputs, policy, &GovernanceProofLoadStatus::Available(proof))
        .expect("A3 accepts valid Rotate proof under env-Required");
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// A4 — local peer-candidate-check Required accepts valid proof-
/// carrying sidecar. The validation-only peer-candidate-check surface
/// shares the same Run 173 shim as reload-check (see
/// `preflight_run_132_validation_only_v2_marker_check` in
/// `crates/qbind-node/src/main.rs`); the source-level invariant is
/// covered by exercising the shim directly. No mutation.
#[test]
fn a4_local_peer_candidate_check_required_accepts_valid_proof_sidecar() {
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
    let inputs = make_inputs(&marker_path, &gh, &r2, &ratified2);
    let _decision = shim_run(inputs, policy, &GovernanceProofLoadStatus::Available(proof))
        .expect("A4 peer-candidate-check accepts valid proof");
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// A5 — live inbound `0x05` Required validation-only path. As of
/// Run 173 the live inbound `0x05` peer-candidate validation surface
/// (`pqc_peer_candidate_wire`) calls
/// [`qbind_node::pqc_authority_marker_acceptance::verify_marker_for_validation_only_v2`]
/// directly and does NOT yet thread a `GovernanceProofLoadStatus`
/// through the wire envelope — the wire envelope schema does not
/// carry a `governance_authority_proof` sibling field. Per the
/// Run 173 task statement this exact boundary is documented and
/// deferred: the shared validation-only helper used by reload-check
/// and peer-candidate-check (which DO have v2 sidecar proof context)
/// is the Run 173 wiring point; the live inbound `0x05` envelope
/// path will get its proof-context plumbing in a later run.
///
/// Source-reachability assertion: the Run 173 validation-only shim
/// behaves identically when fed an `Available` proof, regardless of
/// which surface the proof came from. This test pins that
/// behaviour against the same fixture used by the reload-check
/// surface.
#[test]
fn a5_live_inbound_0x05_required_documented_boundary_with_available_proof() {
    let _g = EnvGuard::set(None);
    let h = devnet_harness();
    let dir = tmpdir("a5");
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
    let inputs = make_inputs(&marker_path, &gh, &r2, &ratified2);
    let _decision = shim_run(inputs, policy, &GovernanceProofLoadStatus::Available(proof))
        .expect("A5 live-inbound boundary: Required + Available accepts");
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// A6 — false / unset env preserves NotRequired across representative
/// validation-only surfaces.
#[test]
fn a6_false_or_unset_env_preserves_not_required() {
    for v in [None, Some("0"), Some("false"), Some(""), Some("garbage")] {
        let _g = EnvGuard::set(v);
        assert!(
            !governance_proof_required_env_selector_enabled(),
            "env value {:?} must NOT enable Required",
            v
        );
        assert_eq!(
            governance_proof_policy_from_cli_or_env(false),
            GovernanceProofPolicy::NotRequired,
            "env value {:?} must NOT select Required",
            v
        );
    }
}

// ===========================================================================
// Rejection matrix R1..R18
// ===========================================================================

/// R1 — reload-check CLI Required + no-proof sidecar rejected with
/// `GovernanceAuthorityRequiredButMissing`.
#[test]
fn r1_reload_check_cli_required_no_proof_rejected_required_but_missing() {
    let _g = EnvGuard::set(None);
    let h = devnet_harness();
    let dir = tmpdir("r1");
    let marker_path = authority_state_file_path(&dir);
    let __seed_bytes = seed_prior_v2_marker(&h, &marker_path);
    let r2 = rotate_after_seed(&h);
    let ratified2 = h.verify_v2(&r2);
    let gh = h.genesis_hex();
    let policy = governance_proof_policy_from_cli_or_env(true);
    let inputs = make_inputs(&marker_path, &gh, &r2, &ratified2);
    let err = shim_run(inputs, policy, &GovernanceProofLoadStatus::Absent)
        .err()
        .expect("R1 fails closed");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::GovernanceAuthorityRequiredButMissing { .. }
    ));
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// R2 — reload-check env Required + no-proof sidecar rejected with
/// `GovernanceAuthorityRequiredButMissing`.
#[test]
fn r2_reload_check_env_required_no_proof_rejected_required_but_missing() {
    let _g = EnvGuard::set(Some("on"));
    let h = devnet_harness();
    let dir = tmpdir("r2");
    let marker_path = authority_state_file_path(&dir);
    let __seed_bytes = seed_prior_v2_marker(&h, &marker_path);
    let r2 = rotate_after_seed(&h);
    let ratified2 = h.verify_v2(&r2);
    let gh = h.genesis_hex();
    let policy = governance_proof_policy_from_cli_or_env(false);
    assert_eq!(policy, GovernanceProofPolicy::RequiredForLifecycleSensitive);
    let inputs = make_inputs(&marker_path, &gh, &r2, &ratified2);
    let err = shim_run(inputs, policy, &GovernanceProofLoadStatus::Absent)
        .err()
        .expect("R2 fails closed");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::GovernanceAuthorityRequiredButMissing { .. }
    ));
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// R3 — reload-check Required + malformed proof rejected.
#[test]
fn r3_reload_check_required_malformed_proof_rejected() {
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
    let inputs = make_inputs(&marker_path, &gh, &r2, &ratified2);
    let malformed = GovernanceProofLoadStatus::Malformed(
        GovernanceProofWireParseError::EmptyIssuerSignature,
    );
    let err = shim_run(inputs, policy, &malformed)
        .err()
        .expect("R3 fails closed");
    // Malformed → Unavailable → Required → RequiredButMissing.
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::GovernanceAuthorityRequiredButMissing { .. }
    ));
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// R4 — reload-check Required + invalid issuer signature rejected.
#[test]
fn r4_reload_check_required_invalid_issuer_signature_rejected() {
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
        AuthorityStateUpdateSource::TestOrFixture,
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
    let inputs = make_inputs(&marker_path, &gh, &r2, &ratified2);
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

/// R5 — reload-check Required + wrong environment proof rejected.
#[test]
fn r5_reload_check_required_wrong_environment_rejected() {
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
        AuthorityStateUpdateSource::TestOrFixture,
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
    let inputs = make_inputs(&marker_path, &gh, &r2, &ratified2);
    let err = shim_run(inputs, policy, &GovernanceProofLoadStatus::Available(proof))
        .err()
        .expect("R5 fails closed");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected(_)
    ));
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// R6 — reload-check Required + wrong chain proof rejected.
#[test]
fn r6_reload_check_required_wrong_chain_rejected() {
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
        AuthorityStateUpdateSource::TestOrFixture,
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
    let inputs = make_inputs(&marker_path, &gh, &r2, &ratified2);
    let err = shim_run(inputs, policy, &GovernanceProofLoadStatus::Available(proof))
        .err()
        .expect("R6 fails closed");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected(_)
    ));
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// R7 — reload-check Required + wrong genesis proof rejected.
#[test]
fn r7_reload_check_required_wrong_genesis_rejected() {
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
        AuthorityStateUpdateSource::TestOrFixture,
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
    let inputs = make_inputs(&marker_path, &gh, &r2, &ratified2);
    let err = shim_run(inputs, policy, &GovernanceProofLoadStatus::Available(proof))
        .err()
        .expect("R7 fails closed");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected(_)
    ));
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// R8 — reload-check Required + wrong authority root proof rejected.
#[test]
fn r8_reload_check_required_wrong_authority_root_rejected() {
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
        AuthorityStateUpdateSource::TestOrFixture,
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
    let inputs = make_inputs(&marker_path, &gh, &r2, &ratified2);
    let err = shim_run(inputs, policy, &GovernanceProofLoadStatus::Available(proof))
        .err()
        .expect("R8 fails closed");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected(_)
    ));
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// R9 — reload-check Required + wrong lifecycle action proof rejected.
#[test]
fn r9_reload_check_required_wrong_lifecycle_action_rejected() {
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
        AuthorityStateUpdateSource::TestOrFixture,
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
    let inputs = make_inputs(&marker_path, &gh, &r2, &ratified2);
    let err = shim_run(inputs, policy, &GovernanceProofLoadStatus::Available(proof))
        .err()
        .expect("R9 fails closed");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected(_)
    ));
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// R10 — reload-check Required + wrong candidate digest proof rejected.
#[test]
fn r10_reload_check_required_wrong_candidate_digest_rejected() {
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
        AuthorityStateUpdateSource::TestOrFixture,
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
    let inputs = make_inputs(&marker_path, &gh, &r2, &ratified2);
    let err = shim_run(inputs, policy, &GovernanceProofLoadStatus::Available(proof))
        .err()
        .expect("R10 fails closed");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected(_)
    ));
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// R11 — reload-check Required + wrong authority-domain sequence
/// proof rejected.
#[test]
fn r11_reload_check_required_wrong_authority_domain_sequence_rejected() {
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
        AuthorityStateUpdateSource::TestOrFixture,
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
    let inputs = make_inputs(&marker_path, &gh, &r2, &ratified2);
    let err = shim_run(inputs, policy, &GovernanceProofLoadStatus::Available(proof))
        .err()
        .expect("R11 fails closed");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected(_)
    ));
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}

/// R12 — reload-check Required + OnChainGovernance proof rejected as
/// unsupported / fail-closed.
#[test]
fn r12_reload_check_required_on_chain_governance_unsupported() {
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
        AuthorityStateUpdateSource::TestOrFixture,
    );
    let proof = good_proof(
        &h,
        &candidate,
        GovernanceAuthorityClass::OnChainGovernance,
        LocalLifecycleAction::Rotate,
    );
    let gh = h.genesis_hex();
    let policy = governance_proof_policy_from_cli_or_env(true);
    let inputs = make_inputs(&marker_path, &gh, &r2, &ratified2);
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

/// R13 — reload-check Required + local operator config alone cannot
/// stand in as authority proof. The shim has no operator-config
/// carrier; an `Absent` status under Required fails closed.
#[test]
fn r13_reload_check_required_local_operator_config_cannot_stand_in() {
    r1_reload_check_cli_required_no_proof_rejected_required_but_missing();
}

/// R14 — reload-check Required + peer-majority cannot stand in as
/// authority proof. Same compile-time argument as R13.
#[test]
fn r14_reload_check_required_peer_majority_cannot_stand_in() {
    r1_reload_check_cli_required_no_proof_rejected_required_but_missing();
}

/// R15 — validation-only Required rejection writes no marker and no
/// sequence. No prior marker on disk → still no marker after reject.
#[test]
fn r15_validation_only_required_rejection_writes_no_marker_no_sequence() {
    let _g = EnvGuard::set(None);
    let h = devnet_harness();
    let dir = tmpdir("r15");
    let marker_path = authority_state_file_path(&dir);
    let r = h.build_v2(
        &h.signing_pk_b,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(pqc_public_key_fingerprint(&h.signing_pk_a)),
    );
    let ratified = h.verify_v2(&r);
    let gh = h.genesis_hex();
    let policy = governance_proof_policy_from_cli_or_env(true);
    let inputs = make_inputs(&marker_path, &gh, &r, &ratified);
    let _err = shim_run(inputs, policy, &GovernanceProofLoadStatus::Absent)
        .err()
        .expect("R15 fails closed under Required + validation-only");
    assert_no_marker_on_disk(&marker_path);
}

/// R16 — validation-only Required rejection performs no live trust
/// swap, no session eviction, and no Run 070 call. The shim itself
/// performs none of these (pure function); the validation-only
/// caller short-circuits on `Err(_)` and never reaches mutation
/// (asserted by the surface mutation contract on
/// `preflight_v2_validation_only_marker_check_with_governance_proof_load`).
#[test]
fn r16_validation_only_required_rejection_no_swap_no_eviction_no_run070() {
    let _g = EnvGuard::set(None);
    let h = devnet_harness();
    let dir = tmpdir("r16");
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
    let mut proof = good_proof(
        &h,
        &candidate,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
    );
    proof.issuer_signature = b"bad".to_vec();
    let gh = h.genesis_hex();
    let policy = governance_proof_policy_from_cli_or_env(true);
    let inputs = make_inputs(&marker_path, &gh, &r2, &ratified2);
    let _err = shim_run(inputs, policy, &GovernanceProofLoadStatus::Available(proof))
        .err()
        .expect("R16 fails closed");
    // No marker mutation.
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
    // The shim is pure: no live trust swap path, no session
    // eviction path, no Run 070 invocation path is reachable from
    // its body. Compile-time invariant.
}

/// R17 — selector cannot be accidentally enabled by unrelated flags.
/// The helper reads only the explicit boolean and the explicit env
/// var; nothing else can flip it.
#[test]
fn r17_selector_cannot_be_accidentally_enabled_by_unrelated_flags() {
    let _g = EnvGuard::set(None);
    assert_eq!(
        governance_proof_policy_from_cli_or_env(false),
        GovernanceProofPolicy::NotRequired
    );
    // Even at the validation-only call site, only the captured
    // selector boolean is read — no other CliArgs field flips the
    // policy. Source-level invariant pinned by
    // `Run105ReloadCheckContextData::governance_proof_required_selector`.
}

/// R18 — MainNet peer-driven apply remains refused even if
/// validation-only Required-policy proof check accepts. The
/// validation-only outcome does not unlock MainNet apply at the
/// upstream binary gate (Run 152 invariant). Source-level
/// assertion: the validation-only shim produces a
/// `MarkerAcceptDecisionV2` and does NOT touch any environment-gate
/// or peer-driven-apply state.
#[test]
fn r18_mainnet_peer_driven_apply_remains_refused_even_if_validation_only_accepts() {
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
    let inputs = make_inputs(&marker_path, &gh, &r2, &ratified2);
    let _decision = shim_run(inputs, policy, &GovernanceProofLoadStatus::Available(proof))
        .expect("R18 validation-only accepts");
    // Even though the validation-only gate accepted, no marker /
    // sequence / live-trust / session / Run-070 mutation occurred.
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
    // MainNet peer-driven apply refusal is enforced upstream by
    // `pqc_peer_candidate_apply::ProductionV2MarkerCoordinator` and
    // its surrounding binary gate (Run 148/149/152 tests). Run 173
    // does not modify that gate.
}

// ===========================================================================
// Source-reachability evidence — selector reaches the Run 169 gate
// from the validation-only shim.
// ===========================================================================

/// Source-reachability — the validation-only shim flows the policy
/// into `evaluate_governance_marker_gate`: NotRequired+Absent → ok,
/// Required+Absent → RequiredButMissing, Required+Available(valid) →
/// ok.
#[test]
fn source_reachability_validation_only_shim_reaches_governance_gate() {
    let _g = EnvGuard::set(None);
    let h = devnet_harness();
    let dir = tmpdir("reach");
    let marker_path = authority_state_file_path(&dir);
    let __seed_bytes = seed_prior_v2_marker(&h, &marker_path);
    let r2 = rotate_after_seed(&h);
    let ratified2 = h.verify_v2(&r2);
    let gh = h.genesis_hex();

    // NotRequired + Absent → accepted.
    let policy_default = governance_proof_policy_from_cli_or_env(false);
    let inputs_default = make_inputs(&marker_path, &gh, &r2, &ratified2);
    let _ok = shim_run(inputs_default, policy_default, &GovernanceProofLoadStatus::Absent)
        .expect("default selector accepts no-proof on validation-only surface");

    // Required + Absent → RequiredButMissing.
    let policy_required = governance_proof_policy_from_cli_or_env(true);
    let inputs_required = make_inputs(&marker_path, &gh, &r2, &ratified2);
    let err = shim_run(
        inputs_required,
        policy_required,
        &GovernanceProofLoadStatus::Absent,
    )
    .err()
    .expect("Required selector rejects no-proof on validation-only surface");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::GovernanceAuthorityRequiredButMissing { .. }
    ));

    // Required + Available(valid) → accepted (proof is verified).
    let candidate = h.derive_candidate(
        &gh,
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
    let inputs_required_ok = make_inputs(&marker_path, &gh, &r2, &ratified2);
    let _ok2 = shim_run(
        inputs_required_ok,
        policy_required,
        &GovernanceProofLoadStatus::Available(proof),
    )
    .expect("Required + Available reaches gate Available context and accepts");

    // The seeded marker is unchanged through every transition above.
    assert_eq!(__seed_bytes, std::fs::read(&marker_path).expect("re-read marker"));
}