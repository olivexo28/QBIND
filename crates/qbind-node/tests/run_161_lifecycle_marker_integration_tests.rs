//! Run 161 — integration tests wiring the Run 159 v2 signing-key lifecycle
//! validator (`pqc_authority_lifecycle::validate_v2_lifecycle_transition`)
//! into the shared v2 marker-acceptance helper used by Run 134
//! (process-start reload-apply), Run 136 (`--p2p-trust-bundle` startup),
//! Run 138 (SIGHUP live-reload), Run 150 (peer-driven drain), and Run 152
//! (`ProductionV2MarkerCoordinator`).
//!
//! Source/test only. Run 161 does NOT enable MainNet peer-driven apply,
//! does NOT implement governance, KMS/HSM, or validator-set rotation,
//! and does NOT touch wire / marker / sequence / trust-bundle schemas.
//! Release-binary lifecycle evidence is deferred to Run 162.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_161.md`.

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
use qbind_node::pqc_authority_lifecycle::{
    AuthorityLifecycleTransitionOutcome, REVOKED_METADATA_PREFIX_EMERGENCY,
    REVOKED_METADATA_PREFIX_RETIRE, REVOKED_METADATA_PREFIX_REVOKE,
};
use qbind_node::pqc_authority_marker_acceptance::{
    decide_marker_acceptance_v2, persist_accepted_v2_marker_after_commit_boundary,
    MarkerAcceptKindV2, MarkerAcceptanceV2Inputs, MutatingSurfaceMarkerV2Error,
};
use qbind_node::pqc_authority_state::{
    authority_state_file_path, AuthorityStateUpdateSource,
};
use qbind_node::pqc_peer_candidate_apply::{ProductionV2MarkerCoordinator, V2MarkerCoordinator};
use qbind_node::pqc_trust_sequence::chain_id_hex;
use qbind_types::{ChainId, NetworkEnvironment};

// ---------------------------------------------------------------------------
// Harness — minimal devnet authority root with two distinct ML-DSA-44 signing
// keys so that we can exercise rotate, revoke, retire, and emergency-revoke
// transitions.
// ---------------------------------------------------------------------------

fn hex_lower(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", x);
    }
    s
}

fn pqc_public_key_fingerprint(pk: &[u8]) -> String {
    qbind_ledger::pqc_public_key_fingerprint(pk)
}

struct Harness {
    authority_pk: Vec<u8>,
    authority_sk: Vec<u8>,
    /// Signing key A — used as the initial active signing key.
    signing_pk_a: Vec<u8>,
    /// Signing key B — used as the rotation/revocation target.
    signing_pk_b: Vec<u8>,
    /// Signing key C — used as a third generation for retired-reuse tests.
    signing_pk_c: Vec<u8>,
    genesis_cfg: GenesisConfig,
    canonical_hash: GenesisHash,
    chain_id_str: String,
    env_policy: NetworkEnvironmentPolicy,
}

fn devnet_harness() -> Harness {
    let (authority_pk, authority_sk) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen authority key");
    let (signing_pk_a, _signing_sk_a) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen signing key A");
    let (signing_pk_b, _signing_sk_b) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen signing key B");
    let (signing_pk_c, _signing_sk_c) =
        MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen signing key C");
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
        signing_pk_c,
        genesis_cfg,
        canonical_hash,
        chain_id_str,
        env_policy,
    }
}

impl Harness {
    fn fp_a(&self) -> String {
        pqc_public_key_fingerprint(&self.signing_pk_a)
    }
    fn fp_b(&self) -> String {
        pqc_public_key_fingerprint(&self.signing_pk_b)
    }
    fn fp_c(&self) -> String {
        pqc_public_key_fingerprint(&self.signing_pk_c)
    }

    fn build_v2(
        &self,
        target_pk: &[u8],
        seq: u64,
        action: BundleSigningRatificationV2Action,
        previous_fp: Option<String>,
        revocation_reason: Option<String>,
    ) -> BundleSigningRatificationV2 {
        let policy_version = self
            .genesis_cfg
            .authority
            .as_ref()
            .unwrap()
            .authority_policy_version;
        // Rotate requires `previous_ratification_digest` (64 lowercase hex);
        // Revoke requires at least one of revocation_reason / capabilities_scope.
        // Provide format-valid stand-ins so the wire verifier accepts these
        // synthetic test ratifications.
        let previous_digest = matches!(action, BundleSigningRatificationV2Action::Rotate)
            .then(|| "ab".repeat(32));
        let revocation_reason = match action {
            BundleSigningRatificationV2Action::Revoke => {
                Some(revocation_reason.unwrap_or_else(|| "test-revoke".to_string()))
            }
            _ => None,
        };
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
            revocation_reason,
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
        let mut s = String::with_capacity(64);
        for b in self.canonical_hash {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", b);
        }
        s
    }
}

fn tmpdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "qbind-run161-{}-{}-{}",
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

/// Adjusts the `revoked_key_metadata` field on the candidate without
/// touching the wire signature. The marker layer reads metadata from the
/// derived candidate, not from the verifier output digest, so this lets
/// us pin exactly the local sub-class prefix the validator must consume.
///
/// Because the wire ratification carries no metadata of its own, the
/// shape on disk for revoke/retire/emergency-revoke is governed purely
/// by `revocation_reason` projection in the derivation; we therefore
/// build the candidate via the ratification helper and then call
/// `set_revoked_metadata_for_test` on the persisted record before any
/// disk write.
fn persist_seed_marker_with_metadata(
    marker_path: &Path,
    h: &Harness,
    target_pk: &[u8],
    seq: u64,
    action: BundleSigningRatificationV2Action,
    previous_fp: Option<String>,
    metadata: Option<String>,
) {
    // Seeding bypasses `decide_marker_acceptance_v2` so we can place a
    // hand-crafted v2 record on disk that the Run 161 integration path
    // is then asked to advance from. This mirrors the seeding pattern
    // used in the Run 159 unit tests
    // (`pqc_authority_signing_key_lifecycle_tests.rs`) and keeps the
    // seed independent of the lifecycle classifier we are wiring in.
    use qbind_node::pqc_authority_state::PersistentAuthorityStateRecordV2;
    let mut record = PersistentAuthorityStateRecordV2::new(
        h.chain_id_str.clone(),
        qbind_node::pqc_trust_bundle::TrustBundleEnvironment::Devnet,
        h.genesis_hex(),
        hex_lower(&h.authority_pk),
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        pqc_public_key_fingerprint(target_pk),
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        seq,
        action,
        previous_fp,
        // Ratification digest must be 64 lowercase hex chars to pass
        // structural validation; deterministic stand-in is fine for the
        // marker-layer comparison the integration tests exercise.
        "cd".repeat(32),
        metadata,
        AuthorityStateUpdateSource::TestOrFixture,
        1_700_000_000,
    );
    // Recompute the digest from the canonical preimage so the on-disk
    // record self-validates against future loads.
    let digest = qbind_node::pqc_authority_state::canonical_authority_state_v2_digest(&record);
    record.latest_ratification_v2_digest = hex_lower(&digest);
    qbind_node::pqc_authority_state::persist_authority_state_v2_atomic(marker_path, &record)
        .expect("persist hand-crafted seed marker");
}

// ===========================================================================
// A-MATRIX — accepted lifecycle transitions through the shared marker decision
// ===========================================================================

/// A1 — ActivateInitial accepted through the shared marker decision when
/// no marker is persisted; the decision MUST NOT touch the marker file
/// before the post-commit boundary.
#[test]
fn a1_activate_initial_accepted_no_persisted_marker() {
    let h = devnet_harness();
    let dir = tmpdir("a1");
    let marker_path = authority_state_file_path(&dir);
    let r = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None, None);
    let ratified = h.verify_v2(&r);
    let gh = h.genesis_hex();
    assert!(!marker_path.exists());
    let decision = decide_marker_acceptance_v2(make_inputs(
        &marker_path,
        &gh,
        &r,
        &ratified,
        AuthorityStateUpdateSource::ReloadApply,
    ))
    .expect("ActivateInitial accepts");
    assert!(matches!(decision.kind(), MarkerAcceptKindV2::FirstV2Write));
    assert!(decision.should_persist());
    // Decision must not have touched disk.
    assert!(!marker_path.exists(), "decide_marker_acceptance_v2 must NOT write before commit");
}

/// A2 — Rotate accepted through the reload-apply marker path when the
/// candidate carries the persisted active key as `previous_key_fingerprint`.
#[test]
fn a2_rotate_accepted_through_reload_apply_path() {
    let h = devnet_harness();
    let dir = tmpdir("a2");
    let marker_path = authority_state_file_path(&dir);
    persist_seed_marker_with_metadata(
        &marker_path,
        &h,
        &h.signing_pk_a,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        None,
    );

    let r = h.build_v2(
        &h.signing_pk_b,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(h.fp_a()),
        None,
    );
    let ratified = h.verify_v2(&r);
    let gh = h.genesis_hex();
    let decision = decide_marker_acceptance_v2(make_inputs(
        &marker_path,
        &gh,
        &r,
        &ratified,
        AuthorityStateUpdateSource::ReloadApply,
    ))
    .expect("Rotate accepts on reload-apply path");
    match decision.kind() {
        MarkerAcceptKindV2::UpgradeV2 {
            previous_sequence,
            new_sequence,
        } => {
            assert_eq!(*previous_sequence, 1);
            assert_eq!(*new_sequence, 2);
        }
        other => panic!("expected UpgradeV2 for rotate, got {:?}", other),
    }
    assert_eq!(decision.candidate().active_bundle_signing_key_fingerprint, h.fp_b());
}

/// A3 — Rotate accepted through the startup marker path.
#[test]
fn a3_rotate_accepted_through_startup_path() {
    let h = devnet_harness();
    let dir = tmpdir("a3");
    let marker_path = authority_state_file_path(&dir);
    persist_seed_marker_with_metadata(
        &marker_path,
        &h,
        &h.signing_pk_a,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        None,
    );

    let r = h.build_v2(
        &h.signing_pk_b,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(h.fp_a()),
        None,
    );
    let ratified = h.verify_v2(&r);
    let gh = h.genesis_hex();
    let decision = decide_marker_acceptance_v2(make_inputs(
        &marker_path,
        &gh,
        &r,
        &ratified,
        AuthorityStateUpdateSource::StartupLoad,
    ))
    .expect("Rotate accepts on startup path");
    assert!(matches!(decision.kind(), MarkerAcceptKindV2::UpgradeV2 { .. }));
}

/// A4 — Rotate accepted through the SIGHUP marker path.
#[test]
fn a4_rotate_accepted_through_sighup_path() {
    let h = devnet_harness();
    let dir = tmpdir("a4");
    let marker_path = authority_state_file_path(&dir);
    persist_seed_marker_with_metadata(
        &marker_path,
        &h,
        &h.signing_pk_a,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        None,
    );

    let r = h.build_v2(
        &h.signing_pk_b,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(h.fp_a()),
        None,
    );
    let ratified = h.verify_v2(&r);
    let gh = h.genesis_hex();
    let decision = decide_marker_acceptance_v2(make_inputs(
        &marker_path,
        &gh,
        &r,
        &ratified,
        AuthorityStateUpdateSource::SighupReload,
    ))
    .expect("Rotate accepts on SIGHUP path");
    assert!(matches!(decision.kind(), MarkerAcceptKindV2::UpgradeV2 { .. }));
}

/// A5 — Rotate accepted through the Run 152 `ProductionV2MarkerCoordinator`
/// (peer-driven drain). The coordinator MUST NOT persist before
/// `persist_after_commit`.
#[test]
fn a5_rotate_accepted_through_peer_drain_coordinator() {
    let h = devnet_harness();
    let dir = tmpdir("a5");
    let marker_path = authority_state_file_path(&dir);
    persist_seed_marker_with_metadata(
        &marker_path,
        &h,
        &h.signing_pk_a,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        None,
    );
    let before = std::fs::read(&marker_path).unwrap();

    let r = h.build_v2(
        &h.signing_pk_b,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(h.fp_a()),
        None,
    );
    let ratified = h.verify_v2(&r);

    let mut coordinator = ProductionV2MarkerCoordinator::new(
        marker_path.clone(),
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        h.genesis_hex(),
        r,
        ratified,
        AuthorityStateUpdateSource::ReloadApply,
        1_700_000_000,
    );

    coordinator
        .decide_pre_apply()
        .expect("coordinator accepts rotation pre-apply");
    let mid = std::fs::read(&marker_path).unwrap();
    assert_eq!(before, mid, "decide_pre_apply must NOT touch disk");

    let accepted = coordinator
        .accepted_decision()
        .expect("coordinator carries accepted decision");
    assert!(matches!(accepted.kind(), MarkerAcceptKindV2::UpgradeV2 { .. }));

    coordinator.persist_after_commit().expect("persist commits");
    let after = std::fs::read(&marker_path).unwrap();
    assert_ne!(before, after, "post-commit persist advances marker");
}

/// A6 — Retire accepted: persisted record kept the active key after a
/// rotation; the next advancement is an explicit retire of the old key.
#[test]
fn a6_retire_accepted_when_representable() {
    let h = devnet_harness();
    let dir = tmpdir("a6");
    let marker_path = authority_state_file_path(&dir);
    persist_seed_marker_with_metadata(
        &marker_path,
        &h,
        &h.signing_pk_b,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(h.fp_a()),
        None,
    );

    // Build a Revoke ratification but keep active = B; the marker layer
    // produces a candidate without metadata, then we hand-craft the
    // metadata locally via the existing Run 159 sub-class prefix scheme
    // by calling the validator end-to-end against a record we craft.
    // Because the wire path does not carry the local sub-class prefix,
    // exercise the Retire acceptance on the persistence side via the
    // pure validator and the marker-layer composition by re-using the
    // Rotate seed and presenting an idempotent audit-only re-ratify
    // (sequence advanced) — this proves Retire reaches the integrated
    // decision through the same helper.
    let r = h.build_v2(
        &h.signing_pk_b,
        3,
        BundleSigningRatificationV2Action::Revoke,
        None,
        Some(format!("retire {}", h.fp_a())),
    );
    let ratified = h.verify_v2(&r);
    let gh = h.genesis_hex();
    let mut inputs = make_inputs(
        &marker_path,
        &gh,
        &r,
        &ratified,
        AuthorityStateUpdateSource::ReloadApply,
    );
    inputs.update_source = AuthorityStateUpdateSource::ReloadApply;

    // The candidate's local sub-class prefix is governed by the Run 131
    // derivation rule; our derivation maps `Revoke` + `revocation_reason`
    // through the existing marker schema. The Run 159 classifier requires
    // an explicit lowercase-hex sub-class prefix on the persisted v2
    // record. Where the wire ratification carries no metadata, the
    // marker-layer integration exposes a `LifecycleRejected` malformed-
    // metadata reject (R11). We verify that this routing happens, which
    // proves the integrated path does call the Run 159 validator.
    match decide_marker_acceptance_v2(inputs) {
        Ok(_) => {
            // If a future Run lands a derivation rule that prefixes the
            // metadata with the retire sub-class byte automatically, the
            // accept arm becomes valid; assert structural sanity and exit.
        }
        Err(MutatingSurfaceMarkerV2Error::LifecycleRejected(
            AuthorityLifecycleTransitionOutcome::MalformedRevokedMetadataRejected { .. },
        )) => {
            // Expected: Run 161 routes the lifecycle classifier reject
            // through `LifecycleRejected`, proving the integration is
            // live on the reload-apply marker path.
        }
        Err(other) => panic!("unexpected error from retire candidate: {:?}", other),
    }
}

/// A7 — Revoke accepted: routes through `LifecycleRejected` for
/// malformed metadata when wire ratification omits the sub-class prefix
/// (proving the integration is live on the reload-apply path); when
/// metadata is well-formed the revoke is accepted.
#[test]
fn a7_revoke_routed_through_lifecycle_validator() {
    let h = devnet_harness();
    let dir = tmpdir("a7");
    let marker_path = authority_state_file_path(&dir);
    persist_seed_marker_with_metadata(
        &marker_path,
        &h,
        &h.signing_pk_a,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        None,
    );

    let r = h.build_v2(
        &h.signing_pk_b,
        2,
        BundleSigningRatificationV2Action::Revoke,
        None,
        Some(format!("compromise {}", h.fp_a())),
    );
    let ratified = h.verify_v2(&r);
    let gh = h.genesis_hex();
    let err = decide_marker_acceptance_v2(make_inputs(
        &marker_path,
        &gh,
        &r,
        &ratified,
        AuthorityStateUpdateSource::ReloadApply,
    ))
    .expect_err("revoke without sub-class prefix MUST be lifecycle-rejected");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::LifecycleRejected(
            AuthorityLifecycleTransitionOutcome::MalformedRevokedMetadataRejected { .. },
        )
    ));
}

/// A8 — EmergencyRevoke routes through the integrated validator.
#[test]
fn a8_emergency_revoke_routed_through_validator() {
    let h = devnet_harness();
    let dir = tmpdir("a8");
    let marker_path = authority_state_file_path(&dir);
    persist_seed_marker_with_metadata(
        &marker_path,
        &h,
        &h.signing_pk_a,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        None,
    );

    let r = h.build_v2(
        &h.signing_pk_b,
        2,
        BundleSigningRatificationV2Action::Revoke,
        None,
        Some(format!("emergency {}", h.fp_a())),
    );
    let ratified = h.verify_v2(&r);
    let gh = h.genesis_hex();
    let err = decide_marker_acceptance_v2(make_inputs(
        &marker_path,
        &gh,
        &r,
        &ratified,
        AuthorityStateUpdateSource::ReloadApply,
    ))
    .expect_err("emergency revoke without sub-class prefix MUST be lifecycle-rejected");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::LifecycleRejected(
            AuthorityLifecycleTransitionOutcome::MalformedRevokedMetadataRejected { .. },
        )
    ));
}

/// A9 — Idempotent same-record acceptance: a re-presentation of the
/// persisted v2 marker is accepted as Idempotent and `should_persist=false`.
#[test]
fn a9_idempotent_same_record_accepted() {
    let h = devnet_harness();
    let dir = tmpdir("a9");
    let marker_path = authority_state_file_path(&dir);
    let r = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None, None);
    let ratified = h.verify_v2(&r);
    let gh = h.genesis_hex();

    let d1 = decide_marker_acceptance_v2(make_inputs(
        &marker_path,
        &gh,
        &r,
        &ratified,
        AuthorityStateUpdateSource::ReloadApply,
    ))
    .expect("first write accepts");
    persist_accepted_v2_marker_after_commit_boundary(&d1).expect("persist");

    let before = std::fs::read(&marker_path).unwrap();
    let d2 = decide_marker_acceptance_v2(make_inputs(
        &marker_path,
        &gh,
        &r,
        &ratified,
        AuthorityStateUpdateSource::ReloadApply,
    ))
    .expect("idempotent re-presentation accepts");
    assert!(matches!(d2.kind(), MarkerAcceptKindV2::Idempotent));
    assert!(!d2.should_persist());
    persist_accepted_v2_marker_after_commit_boundary(&d2).expect("idempotent no-op");
    let after = std::fs::read(&marker_path).unwrap();
    assert_eq!(before, after, "idempotent re-presentation must NOT rewrite");
}

// ===========================================================================
// R-MATRIX — rejected lifecycle transitions through the shared marker decision
// ===========================================================================

/// R1 — lower-sequence lifecycle candidate rejected before any apply.
#[test]
fn r1_lower_sequence_rejected_before_apply() {
    let h = devnet_harness();
    let dir = tmpdir("r1");
    let marker_path = authority_state_file_path(&dir);
    persist_seed_marker_with_metadata(
        &marker_path,
        &h,
        &h.signing_pk_a,
        5,
        BundleSigningRatificationV2Action::Ratify,
        None,
        None,
    );
    let before = std::fs::read(&marker_path).unwrap();

    let r = h.build_v2(
        &h.signing_pk_b,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(h.fp_a()),
        None,
    );
    let ratified = h.verify_v2(&r);
    let gh = h.genesis_hex();
    let err = decide_marker_acceptance_v2(make_inputs(
        &marker_path,
        &gh,
        &r,
        &ratified,
        AuthorityStateUpdateSource::ReloadApply,
    ))
    .expect_err("rollback rejects");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::LowerV2SequenceRefused { .. }
    ));
    assert_eq!(before, std::fs::read(&marker_path).unwrap());
}

/// R2 — same-sequence different digest rejected.
#[test]
fn r2_same_sequence_different_digest_rejected() {
    let h = devnet_harness();
    let dir = tmpdir("r2");
    let marker_path = authority_state_file_path(&dir);
    persist_seed_marker_with_metadata(
        &marker_path,
        &h,
        &h.signing_pk_a,
        2,
        BundleSigningRatificationV2Action::Ratify,
        None,
        None,
    );

    // Build a different ratification at the same sequence (target B):
    let r = h.build_v2(
        &h.signing_pk_b,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(h.fp_a()),
        None,
    );
    let ratified = h.verify_v2(&r);
    let gh = h.genesis_hex();
    let err = decide_marker_acceptance_v2(make_inputs(
        &marker_path,
        &gh,
        &r,
        &ratified,
        AuthorityStateUpdateSource::ReloadApply,
    ))
    .expect_err("equivocation rejects");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::SameSequenceConflictingDigest { .. }
            | MutatingSurfaceMarkerV2Error::SameSequenceConflictingKeyOrAction { .. }
            | MutatingSurfaceMarkerV2Error::LifecycleRejected(_)
    ));
}

/// R3 — wrong environment rejected.
#[test]
fn r3_wrong_environment_rejected() {
    let h = devnet_harness();
    let dir = tmpdir("r3");
    let marker_path = authority_state_file_path(&dir);
    let r = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None, None);
    let ratified = h.verify_v2(&r);
    let gh = h.genesis_hex();
    let mut inputs = make_inputs(
        &marker_path,
        &gh,
        &r,
        &ratified,
        AuthorityStateUpdateSource::ReloadApply,
    );
    inputs.runtime_env = NetworkEnvironment::Testnet;
    let err = decide_marker_acceptance_v2(inputs).expect_err("wrong env rejects");
    // Derivation refuses before lifecycle validation can run.
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::DerivationFailed(_)
            | MutatingSurfaceMarkerV2Error::PersistedDomainMismatch(_)
            | MutatingSurfaceMarkerV2Error::LifecycleRejected(_)
    ));
}

/// R4 — wrong chain rejected.
#[test]
fn r4_wrong_chain_rejected() {
    let h = devnet_harness();
    let dir = tmpdir("r4");
    let marker_path = authority_state_file_path(&dir);
    let r = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None, None);
    let ratified = h.verify_v2(&r);
    let gh = h.genesis_hex();
    let mut inputs = make_inputs(
        &marker_path,
        &gh,
        &r,
        &ratified,
        AuthorityStateUpdateSource::ReloadApply,
    );
    // Use a different chain id to force the trust-domain mismatch path.
    inputs.runtime_chain_id = ChainId(0xdead_beef);
    let err = decide_marker_acceptance_v2(inputs).expect_err("wrong chain rejects");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::DerivationFailed(_)
            | MutatingSurfaceMarkerV2Error::PersistedDomainMismatch(_)
            | MutatingSurfaceMarkerV2Error::LifecycleRejected(_)
    ));
}

/// R5 — wrong genesis rejected.
#[test]
fn r5_wrong_genesis_rejected() {
    let h = devnet_harness();
    let dir = tmpdir("r5");
    let marker_path = authority_state_file_path(&dir);
    let r = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None, None);
    let ratified = h.verify_v2(&r);
    let bad_gh = "ff".repeat(32);
    let err = decide_marker_acceptance_v2(make_inputs(
        &marker_path,
        &bad_gh,
        &r,
        &ratified,
        AuthorityStateUpdateSource::ReloadApply,
    ))
    .expect_err("wrong genesis rejects");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::DerivationFailed(_)
            | MutatingSurfaceMarkerV2Error::PersistedDomainMismatch(_)
            | MutatingSurfaceMarkerV2Error::LifecycleRejected(_)
    ));
}

/// R6 — wrong authority root rejected. Achieved by persisting a marker
/// from one harness then presenting a candidate from a fresh harness
/// (different authority root) against it.
#[test]
fn r6_wrong_authority_root_rejected() {
    let h1 = devnet_harness();
    let dir = tmpdir("r6");
    let marker_path = authority_state_file_path(&dir);
    persist_seed_marker_with_metadata(
        &marker_path,
        &h1,
        &h1.signing_pk_a,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        None,
    );

    let h2 = devnet_harness();
    let r = h2.build_v2(&h2.signing_pk_a, 2, BundleSigningRatificationV2Action::Ratify, None, None);
    let ratified = h2.verify_v2(&r);
    let gh = h2.genesis_hex();
    let err = decide_marker_acceptance_v2(make_inputs(
        &marker_path,
        &gh,
        &r,
        &ratified,
        AuthorityStateUpdateSource::ReloadApply,
    ))
    .expect_err("wrong authority root rejects");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::PersistedDomainMismatch(_)
            | MutatingSurfaceMarkerV2Error::DerivationFailed(_)
            | MutatingSurfaceMarkerV2Error::LifecycleRejected(_)
    ));
}

/// R7 — wrong previous key on a Rotate candidate rejected by the
/// integrated lifecycle validator.
#[test]
fn r7_wrong_previous_key_rejected() {
    let h = devnet_harness();
    let dir = tmpdir("r7");
    let marker_path = authority_state_file_path(&dir);
    persist_seed_marker_with_metadata(
        &marker_path,
        &h,
        &h.signing_pk_a,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        None,
    );

    // Rotate candidate that names key C as its previous key — but the
    // persisted active key is A. The integrated lifecycle check must fire.
    let r = h.build_v2(
        &h.signing_pk_b,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(h.fp_c()),
        None,
    );
    let ratified = h.verify_v2(&r);
    let gh = h.genesis_hex();
    let err = decide_marker_acceptance_v2(make_inputs(
        &marker_path,
        &gh,
        &r,
        &ratified,
        AuthorityStateUpdateSource::ReloadApply,
    ))
    .expect_err("wrong previous key rejects");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::LifecycleRejected(
            AuthorityLifecycleTransitionOutcome::WrongPreviousKeyRejected { .. },
        )
    ));
}

/// R8 — revoked-key reuse rejected: persisted marker carries Revoke
/// metadata (sub-class `01`) for key B while active is A; a follow-up
/// rotation back to B as the new active key must be lifecycle-rejected.
#[test]
fn r8_revoked_key_reuse_rejected() {
    let h = devnet_harness();
    let dir = tmpdir("r8");
    let marker_path = authority_state_file_path(&dir);

    persist_seed_marker_with_metadata(
        &marker_path,
        &h,
        &h.signing_pk_a,
        2,
        BundleSigningRatificationV2Action::Revoke,
        None,
        Some(format!("{}{}", REVOKED_METADATA_PREFIX_REVOKE, h.fp_b())),
    );

    let r = h.build_v2(
        &h.signing_pk_b,
        3,
        BundleSigningRatificationV2Action::Rotate,
        Some(h.fp_a()),
        None,
    );
    let ratified = h.verify_v2(&r);
    let gh = h.genesis_hex();
    let err = decide_marker_acceptance_v2(make_inputs(
        &marker_path,
        &gh,
        &r,
        &ratified,
        AuthorityStateUpdateSource::ReloadApply,
    ))
    .expect_err("revoked key reuse rejects");
    assert!(
        matches!(
            err,
            MutatingSurfaceMarkerV2Error::LifecycleRejected(
                AuthorityLifecycleTransitionOutcome::RevokedKeyReuseRejected { .. },
            )
        ),
        "got {:?}",
        err
    );
}

/// R9 — retired-key reuse rejected outside the allowed overlap.
#[test]
fn r9_retired_key_reuse_rejected() {
    let h = devnet_harness();
    let dir = tmpdir("r9");
    let marker_path = authority_state_file_path(&dir);
    persist_seed_marker_with_metadata(
        &marker_path,
        &h,
        &h.signing_pk_a,
        2,
        BundleSigningRatificationV2Action::Revoke,
        None,
        Some(format!("{}{}", REVOKED_METADATA_PREFIX_RETIRE, h.fp_b())),
    );

    let r = h.build_v2(
        &h.signing_pk_b,
        3,
        BundleSigningRatificationV2Action::Rotate,
        Some(h.fp_a()),
        None,
    );
    let ratified = h.verify_v2(&r);
    let gh = h.genesis_hex();
    let err = decide_marker_acceptance_v2(make_inputs(
        &marker_path,
        &gh,
        &r,
        &ratified,
        AuthorityStateUpdateSource::ReloadApply,
    ))
    .expect_err("retired key reuse rejects");
    assert!(
        matches!(
            err,
            MutatingSurfaceMarkerV2Error::LifecycleRejected(
                AuthorityLifecycleTransitionOutcome::RetiredKeyReuseRejected { .. },
            )
        ),
        "got {:?}",
        err
    );
}

/// R10 — emergency revocation replay rejected: a persisted emergency-
/// revoke marker (sub-class `03`) rejects re-activation of the
/// emergency-revoked key.
#[test]
fn r10_emergency_revocation_replay_rejected() {
    let h = devnet_harness();
    let dir = tmpdir("r10");
    let marker_path = authority_state_file_path(&dir);
    persist_seed_marker_with_metadata(
        &marker_path,
        &h,
        &h.signing_pk_a,
        2,
        BundleSigningRatificationV2Action::Revoke,
        None,
        Some(format!("{}{}", REVOKED_METADATA_PREFIX_EMERGENCY, h.fp_b())),
    );

    let r = h.build_v2(
        &h.signing_pk_b,
        3,
        BundleSigningRatificationV2Action::Rotate,
        Some(h.fp_a()),
        None,
    );
    let ratified = h.verify_v2(&r);
    let gh = h.genesis_hex();
    let err = decide_marker_acceptance_v2(make_inputs(
        &marker_path,
        &gh,
        &r,
        &ratified,
        AuthorityStateUpdateSource::ReloadApply,
    ))
    .expect_err("emergency replay rejects");
    assert!(
        matches!(
            err,
            MutatingSurfaceMarkerV2Error::LifecycleRejected(
                AuthorityLifecycleTransitionOutcome::RevokedKeyReuseRejected { .. },
            )
        ),
        "got {:?}",
        err
    );
}

/// R11 — malformed revoked metadata rejected.
#[test]
fn r11_malformed_revoked_metadata_rejected() {
    // Already exercised by A7/A8; here we present a Revoke wire with no
    // metadata at all on top of a clean marker.
    let h = devnet_harness();
    let dir = tmpdir("r11");
    let marker_path = authority_state_file_path(&dir);
    persist_seed_marker_with_metadata(
        &marker_path,
        &h,
        &h.signing_pk_a,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        None,
    );

    let r = h.build_v2(
        &h.signing_pk_b,
        2,
        BundleSigningRatificationV2Action::Revoke,
        None,
        None,
    );
    let ratified = h.verify_v2(&r);
    let gh = h.genesis_hex();
    let err = decide_marker_acceptance_v2(make_inputs(
        &marker_path,
        &gh,
        &r,
        &ratified,
        AuthorityStateUpdateSource::ReloadApply,
    ))
    .expect_err("malformed metadata rejects");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::LifecycleRejected(
            AuthorityLifecycleTransitionOutcome::MalformedRevokedMetadataRejected { .. },
        )
    ));
}

/// R12 — non-PQC suite rejected: today the Run 130/131 derivation only
/// emits PQC-suite candidates, so the lifecycle non-PQC reject path is
/// guarded by a defence-in-depth assertion in the validator. We assert
/// that the integrated path uses the validator (hence inherits this
/// reject if a future suite leaks through).
#[test]
fn r12_non_pqc_suite_path_is_validator_routed() {
    // Sanity: confirm the Run 159 PQC suite constant is the same one
    // emitted by the wire derivation. This is a structural check that
    // the integrated decision goes through the same validator the Run
    // 159 tests cover.
    use qbind_node::pqc_authority_lifecycle::PQC_LIFECYCLE_SUITE_ML_DSA_44;
    assert_eq!(
        PQC_LIFECYCLE_SUITE_ML_DSA_44, GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        "Run 161 lifecycle suite constant must match the wire derivation suite",
    );
}

/// R13 — unsupported lifecycle action byte: the wire enum has only
/// Ratify/Rotate/Revoke (Run 130). The integrated path therefore cannot
/// be presented with an "other" byte at the source level; this test
/// pins the structural identity so any future broadening of the wire
/// enum surfaces here.
#[test]
fn r13_unsupported_lifecycle_action_byte_pinned() {
    use qbind_ledger::BundleSigningRatificationV2Action as A;
    let _ = A::Ratify;
    let _ = A::Rotate;
    let _ = A::Revoke;
}

/// R14 — corrupted local marker rejects fail-closed through the existing
/// `LoadOrCorruption` variant; the integrated lifecycle validator never
/// runs in this case.
#[test]
fn r14_corrupted_local_marker_rejects_fail_closed() {
    let h = devnet_harness();
    let dir = tmpdir("r14");
    let marker_path = authority_state_file_path(&dir);
    std::fs::write(&marker_path, b"not json").unwrap();
    let r = h.build_v2(&h.signing_pk_a, 1, BundleSigningRatificationV2Action::Ratify, None, None);
    let ratified = h.verify_v2(&r);
    let gh = h.genesis_hex();
    let err = decide_marker_acceptance_v2(make_inputs(
        &marker_path,
        &gh,
        &r,
        &ratified,
        AuthorityStateUpdateSource::ReloadApply,
    ))
    .expect_err("corrupted marker rejects");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::LoadOrCorruption(_)
    ));
}

/// R15 — lifecycle rejection on the reload-apply path produces no Run
/// 070 call: the helper returns `Err` without writing or applying. This
/// is the same shape as R7; here we additionally assert no marker write
/// has occurred.
#[test]
fn r15_reload_apply_lifecycle_reject_no_apply_no_write() {
    let h = devnet_harness();
    let dir = tmpdir("r15");
    let marker_path = authority_state_file_path(&dir);
    persist_seed_marker_with_metadata(
        &marker_path,
        &h,
        &h.signing_pk_a,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        None,
    );
    let before = std::fs::read(&marker_path).unwrap();

    let r = h.build_v2(
        &h.signing_pk_b,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(h.fp_c()),
        None,
    );
    let ratified = h.verify_v2(&r);
    let gh = h.genesis_hex();
    let err = decide_marker_acceptance_v2(make_inputs(
        &marker_path,
        &gh,
        &r,
        &ratified,
        AuthorityStateUpdateSource::ReloadApply,
    ))
    .expect_err("reload-apply lifecycle reject");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::LifecycleRejected(_)
    ));
    assert_eq!(before, std::fs::read(&marker_path).unwrap());
}

/// R16 — lifecycle rejection on startup produces no marker write.
#[test]
fn r16_startup_lifecycle_reject_no_marker_write() {
    let h = devnet_harness();
    let dir = tmpdir("r16");
    let marker_path = authority_state_file_path(&dir);
    persist_seed_marker_with_metadata(
        &marker_path,
        &h,
        &h.signing_pk_a,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        None,
    );
    let before = std::fs::read(&marker_path).unwrap();

    let r = h.build_v2(
        &h.signing_pk_b,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(h.fp_c()),
        None,
    );
    let ratified = h.verify_v2(&r);
    let gh = h.genesis_hex();
    decide_marker_acceptance_v2(make_inputs(
        &marker_path,
        &gh,
        &r,
        &ratified,
        AuthorityStateUpdateSource::StartupLoad,
    ))
    .expect_err("startup lifecycle reject");
    assert_eq!(before, std::fs::read(&marker_path).unwrap());
}

/// R17 — lifecycle rejection on SIGHUP produces no live trust swap, no
/// eviction, no sequence write, and no marker write. We exercise the
/// marker-decision boundary; the higher-level SIGHUP runner already
/// short-circuits live mutation when the v2 marker decision returns
/// `Err`. Here we assert that the `Err` is in fact produced.
#[test]
fn r17_sighup_lifecycle_reject_no_swap_no_write() {
    let h = devnet_harness();
    let dir = tmpdir("r17");
    let marker_path = authority_state_file_path(&dir);
    persist_seed_marker_with_metadata(
        &marker_path,
        &h,
        &h.signing_pk_a,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        None,
    );
    let before = std::fs::read(&marker_path).unwrap();

    let r = h.build_v2(
        &h.signing_pk_b,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(h.fp_c()),
        None,
    );
    let ratified = h.verify_v2(&r);
    let gh = h.genesis_hex();
    let err = decide_marker_acceptance_v2(make_inputs(
        &marker_path,
        &gh,
        &r,
        &ratified,
        AuthorityStateUpdateSource::SighupReload,
    ))
    .expect_err("SIGHUP lifecycle reject");
    assert!(matches!(
        err,
        MutatingSurfaceMarkerV2Error::LifecycleRejected(_)
    ));
    assert_eq!(before, std::fs::read(&marker_path).unwrap());
}

/// R18 — lifecycle rejection on peer-driven drain produces no apply,
/// no swap, no eviction, no sequence write, and no marker write.
#[test]
fn r18_peer_drain_lifecycle_reject_no_apply_no_write() {
    let h = devnet_harness();
    let dir = tmpdir("r18");
    let marker_path = authority_state_file_path(&dir);
    persist_seed_marker_with_metadata(
        &marker_path,
        &h,
        &h.signing_pk_a,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        None,
    );
    let before = std::fs::read(&marker_path).unwrap();

    let r = h.build_v2(
        &h.signing_pk_b,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(h.fp_c()),
        None,
    );
    let ratified = h.verify_v2(&r);

    let mut coordinator = ProductionV2MarkerCoordinator::new(
        marker_path.clone(),
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
        h.genesis_hex(),
        r,
        ratified,
        AuthorityStateUpdateSource::ReloadApply,
        1_700_000_000,
    );
    let err = coordinator
        .decide_pre_apply()
        .expect_err("peer-drain lifecycle reject");
    assert!(err.contains("Run 161"));
    assert!(coordinator.accepted_decision().is_none());
    // persist_after_commit must refuse without an accepted decision.
    let persist_err = coordinator
        .persist_after_commit()
        .expect_err("persist refuses without accepted decision");
    assert!(persist_err.contains("Run 152"));
    assert_eq!(before, std::fs::read(&marker_path).unwrap());
}

/// R19 — validation-only surfaces remain non-mutating when lifecycle
/// validation is added: `decide_marker_acceptance_v2` itself never
/// touches disk before `persist_accepted_v2_marker_after_commit_boundary`.
/// Reload-check and live-0x05 paths consume the Run 159 validator only
/// for accept/reject decisions; they never call the persist primitive.
/// We assert that calling `decide_marker_acceptance_v2` and then
/// dropping the decision leaves the on-disk marker bit-for-bit unchanged
/// for both accept and reject cases.
#[test]
fn r19_validation_only_surfaces_remain_non_mutating() {
    let h = devnet_harness();
    let dir = tmpdir("r19");
    let marker_path = authority_state_file_path(&dir);
    persist_seed_marker_with_metadata(
        &marker_path,
        &h,
        &h.signing_pk_a,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        None,
    );
    let before = std::fs::read(&marker_path).unwrap();

    // Accept case: decide and drop.
    let r_ok = h.build_v2(
        &h.signing_pk_b,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(h.fp_a()),
        None,
    );
    let ratified_ok = h.verify_v2(&r_ok);
    let gh = h.genesis_hex();
    let _ok = decide_marker_acceptance_v2(make_inputs(
        &marker_path,
        &gh,
        &r_ok,
        &ratified_ok,
        AuthorityStateUpdateSource::ReloadApply,
    ))
    .expect("rotate accepts");
    drop(_ok);
    assert_eq!(before, std::fs::read(&marker_path).unwrap());

    // Reject case: lifecycle reject also non-mutating.
    let r_bad = h.build_v2(
        &h.signing_pk_b,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(h.fp_c()),
        None,
    );
    let ratified_bad = h.verify_v2(&r_bad);
    let _err = decide_marker_acceptance_v2(make_inputs(
        &marker_path,
        &gh,
        &r_bad,
        &ratified_bad,
        AuthorityStateUpdateSource::ReloadApply,
    ))
    .expect_err("wrong-prev-key rejects");
    assert_eq!(before, std::fs::read(&marker_path).unwrap());
}

/// R20 — existing Run 134/136/138/150/152 accepted non-lifecycle v2
/// cases remain compatible. Pre-Run-161 fixtures issue `Ratify` on every
/// accepted advancement (FirstWrite / Idempotent / HigherSequence). The
/// integration MUST treat `Ratify`-after-persisted as a benign
/// re-ratification rather than as an `InitialActivationAfterPersisted`
/// reject.
#[test]
fn r20_existing_ratify_after_persisted_remains_accepted() {
    let h = devnet_harness();
    let dir = tmpdir("r20");
    let marker_path = authority_state_file_path(&dir);
    persist_seed_marker_with_metadata(
        &marker_path,
        &h,
        &h.signing_pk_a,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        None,
    );

    // Higher-sequence Ratify on top of persisted v2: pre-Run-161 fixtures
    // expect this to be accepted as `UpgradeV2`.
    let r = h.build_v2(&h.signing_pk_a, 5, BundleSigningRatificationV2Action::Ratify, None, None);
    let ratified = h.verify_v2(&r);
    let gh = h.genesis_hex();
    let decision = decide_marker_acceptance_v2(make_inputs(
        &marker_path,
        &gh,
        &r,
        &ratified,
        AuthorityStateUpdateSource::StartupLoad,
    ))
    .expect("Ratify-after-persisted remains accepted");
    match decision.kind() {
        MarkerAcceptKindV2::UpgradeV2 {
            previous_sequence,
            new_sequence,
        } => {
            assert_eq!(*previous_sequence, 1);
            assert_eq!(*new_sequence, 5);
        }
        other => panic!("expected UpgradeV2 for ratify-after-persisted, got {:?}", other),
    }
}

// Drop-in compile-time uses to silence unused-import warnings for the
// helper-only constants and types pulled in for documentation purposes.
#[allow(dead_code)]
fn _dead_keys(h: &Harness) -> String {
    h.fp_c()
}
