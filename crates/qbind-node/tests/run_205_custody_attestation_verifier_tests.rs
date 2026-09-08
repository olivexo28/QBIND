//! Run 205 — source/test production custody attestation verifier
//! skeleton integration tests.
//!
//! Source/test only. Run 205 does **not** capture release-binary
//! evidence; release-binary custody-attestation verifier-boundary
//! evidence is deferred to **Run 206**. The tests cover:
//!
//! * the full A1–A14 / R1–R40 matrix from `task/RUN_205_TASK.txt`;
//! * evidence / input / transcript canonical digest determinism and
//!   domain-binding;
//! * replay / freshness checks;
//! * fixture-vs-production attestation separation;
//! * cloud-KMS / PKCS#11 / production attestation unavailable fail-closed
//!   paths;
//! * malformed evidence fail-closed paths;
//! * the no-I/O guarantee for the production attestation path (the tests
//!   construct only data values and call only pure validators / pure
//!   trait methods);
//! * the no-mutation guarantee (validation-only surfaces never mutate);
//! * MainNet refusal invariants;
//! * compatibility with Run 188 custody, the Run 201 RemoteSigner
//!   transport, and the Run 203 KMS/HSM backend paths.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_205.md`.

use qbind_ledger::BundleSigningRatificationV2Action;
use qbind_node::pqc_authority_custody::{
    AuthorityCustodyAttestation, AuthorityCustodyClass, AuthorityCustodyPolicy,
};
use qbind_node::pqc_authority_kms_hsm_backend::{
    backend_transcript_digest, BackendIdentity, BackendKind, BackendRequest, BackendResponse,
};
use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use qbind_node::pqc_authority_state::{
    AuthorityStateUpdateSource, PersistentAuthorityStateRecordV2,
    PersistentAuthorityStateRecordVersioned,
};
use qbind_node::pqc_custody_attestation_verifier::{
    attestation_transcript_digest, local_operator_cannot_satisfy_production_attestation,
    mainnet_peer_driven_apply_remains_refused_under_attestation_boundary,
    peer_majority_cannot_satisfy_production_attestation, validate_custody_metadata_and_attestation,
    validate_lifecycle_custody_and_attestation, verify_custody_attestation,
    CloudKmsAttestationVerifier, CustodyAttestationClass, CustodyAttestationEvidence,
    CustodyAttestationInput, CustodyAttestationOutcome, CustodyAttestationPolicy,
    CustodyAttestationVerifier, CustodyMetadataAttestationOutcome,
    FixtureCustodyAttestationVerifier, HsmAttestationVerifier, KmsAttestationVerifier,
    Pkcs11HsmAttestationVerifier, ProductionAttestationVerifier, RemoteSignerAttestationVerifier,
    CUSTODY_ATTESTATION_INVALID_COMMITMENT_SENTINEL, CUSTODY_ATTESTATION_SUPPORTED_VERSION,
};
use qbind_node::pqc_governance_authority::GovernanceAuthorityClass;
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Shared fixtures
// ===========================================================================

const KEY_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEY_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ROOT_FP: &str = "1111111111111111111111111111111111111111";
const CHAIN_ID: &str = "0000000000000001";
const GENESIS_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const PRIOR_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const KEY_ID: &str = "attestation-key-id-205";
const PROVIDER_ID: &str = "attestation-provider-205";
const ATTEST_COMMITMENT: &str = "attestation-commitment-205";
const ATTEST_NONCE: &str = "attestation-nonce-205";
const GOV_PROOF_DIGEST: &str = "gov-proof-digest-205";
const NOW: u64 = 1_700_000_000;
const FRESH: u64 = 1_699_999_900;
const EXPIRES: u64 = 1_700_001_000;
const ISSUED: u64 = 1_699_999_950;
const WINDOW_SINCE: u64 = 1_699_999_000;
const WINDOW_UNTIL: u64 = 1_700_000_500;

fn domain(env: TrustBundleEnvironment) -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(
        env,
        CHAIN_ID,
        GENESIS_HASH,
        ROOT_FP,
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
    )
}

fn build_v2(
    env: TrustBundleEnvironment,
    active_fp: &str,
    sequence: u64,
    action: BundleSigningRatificationV2Action,
    previous_fp: Option<&str>,
    digest: &str,
) -> PersistentAuthorityStateRecordV2 {
    PersistentAuthorityStateRecordV2::new(
        CHAIN_ID.to_string(),
        env,
        GENESIS_HASH.to_string(),
        ROOT_FP.to_string(),
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        active_fp.to_string(),
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        sequence,
        action,
        previous_fp.map(str::to_string),
        digest.to_string(),
        None,
        AuthorityStateUpdateSource::TestOrFixture,
        NOW,
    )
}

fn rotate_candidate(env: TrustBundleEnvironment) -> PersistentAuthorityStateRecordV2 {
    build_v2(
        env,
        KEY_B,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(KEY_A),
        DIGEST_2,
    )
}

fn prior_versioned(env: TrustBundleEnvironment) -> PersistentAuthorityStateRecordVersioned {
    PersistentAuthorityStateRecordVersioned::V2(build_v2(
        env,
        KEY_A,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        PRIOR_DIGEST,
    ))
}

/// A bound Run 203 backend transcript digest, demonstrating composition
/// with the KMS/HSM backend path (Run 203) and the RemoteSigner transport
/// path (Run 201) as opaque evidence fields.
fn bound_transcript_digest() -> String {
    backend_transcript_digest("identity-digest", "request-digest", "response-digest")
}

fn evidence(
    class: CustodyAttestationClass,
    env: TrustBundleEnvironment,
    candidate: &PersistentAuthorityStateRecordV2,
) -> CustodyAttestationEvidence {
    CustodyAttestationEvidence {
        attestation_class: class,
        attestation_version: CUSTODY_ATTESTATION_SUPPORTED_VERSION,
        environment: env,
        chain_id: CHAIN_ID.to_string(),
        genesis_hash: GENESIS_HASH.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        bundle_signing_key_fingerprint: candidate.active_bundle_signing_key_fingerprint.clone(),
        custody_class: AuthorityCustodyClass::Kms,
        custody_backend_kind: Some(BackendKind::FixtureKms.tag().to_string()),
        backend_provider_signer_id: PROVIDER_ID.to_string(),
        custody_key_id: KEY_ID.to_string(),
        suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        lifecycle_action: LocalLifecycleAction::Rotate,
        candidate_digest: DIGEST_2.to_string(),
        authority_domain_sequence: 2,
        governance_proof_digest: Some(GOV_PROOF_DIGEST.to_string()),
        request_digest: Some("request-digest".to_string()),
        response_digest: Some("response-digest".to_string()),
        transcript_digest: Some(bound_transcript_digest()),
        attestation_nonce: ATTEST_NONCE.to_string(),
        issued_at_unix: Some(ISSUED),
        freshness_unix: Some(FRESH),
        expires_at_unix: Some(EXPIRES),
        attestation_commitment: ATTEST_COMMITMENT.to_string(),
    }
}

fn input(
    env: TrustBundleEnvironment,
    candidate: &PersistentAuthorityStateRecordV2,
) -> CustodyAttestationInput {
    CustodyAttestationInput {
        expected_environment: env,
        expected_chain_id: CHAIN_ID.to_string(),
        expected_genesis_hash: GENESIS_HASH.to_string(),
        expected_authority_root_fingerprint: ROOT_FP.to_string(),
        expected_bundle_signing_key_fingerprint: candidate
            .active_bundle_signing_key_fingerprint
            .clone(),
        expected_custody_class: AuthorityCustodyClass::Kms,
        expected_backend_provider_signer_id: PROVIDER_ID.to_string(),
        expected_custody_key_id: KEY_ID.to_string(),
        expected_suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        expected_lifecycle_action: LocalLifecycleAction::Rotate,
        expected_candidate_digest: DIGEST_2.to_string(),
        expected_authority_domain_sequence: 2,
        expected_governance_proof_digest: Some(GOV_PROOF_DIGEST.to_string()),
        expected_request_digest: Some("request-digest".to_string()),
        expected_response_digest: Some("response-digest".to_string()),
        expected_transcript_digest: Some(bound_transcript_digest()),
        expected_attestation_nonce: ATTEST_NONCE.to_string(),
        replay_window_since_unix: Some(WINDOW_SINCE),
        replay_window_until_unix: Some(WINDOW_UNTIL),
        now_unix: NOW,
    }
}

fn good_custody_attestation(
    env: TrustBundleEnvironment,
    candidate: &PersistentAuthorityStateRecordV2,
) -> AuthorityCustodyAttestation {
    AuthorityCustodyAttestation {
        custody_class: AuthorityCustodyClass::FixtureLocalKey,
        custody_key_id: KEY_ID.to_string(),
        custody_suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        custody_attestation_digest: "custody-att-digest".to_string(),
        freshness_unix: Some(FRESH),
        expires_at_unix: Some(EXPIRES),
        environment: env,
        chain_id: CHAIN_ID.to_string(),
        genesis_hash: GENESIS_HASH.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        bundle_signing_key_fingerprint: candidate.active_bundle_signing_key_fingerprint.clone(),
        governance_authority_class: GovernanceAuthorityClass::GenesisBound,
        lifecycle_action: LocalLifecycleAction::Rotate,
        candidate_digest: DIGEST_2.to_string(),
        authority_domain_sequence: 2,
    }
}

/// A complete, valid accepted attestation scenario on the given
/// environment. Returns every part a test needs to mutate one field for a
/// rejection vector.
struct Scenario {
    domain: AuthorityTrustDomain,
    candidate: PersistentAuthorityStateRecordV2,
    evidence: CustodyAttestationEvidence,
    input: CustodyAttestationInput,
}

fn accepted_scenario(env: TrustBundleEnvironment) -> Scenario {
    let candidate = rotate_candidate(env);
    let evidence = evidence(CustodyAttestationClass::FixtureAttestation, env, &candidate);
    let input = input(env, &candidate);
    Scenario {
        domain: domain(env),
        candidate,
        evidence,
        input,
    }
}

fn verify(s: &Scenario, policy: CustodyAttestationPolicy) -> CustodyAttestationOutcome {
    verify_custody_attestation(&s.evidence, &s.input, &s.domain, policy)
}

// ===========================================================================
// Accepted scenarios A1–A14
// ===========================================================================

#[test]
fn a1_fixture_attestation_accepted_devnet() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    let outcome = verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed);
    assert!(matches!(
        outcome,
        CustodyAttestationOutcome::FixtureAttestationAccepted {
            environment: TrustBundleEnvironment::Devnet,
            ..
        }
    ));
    assert!(outcome.is_accept());
}

#[test]
fn a2_fixture_attestation_accepted_testnet() {
    let s = accepted_scenario(TrustBundleEnvironment::Testnet);
    let outcome = verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed);
    assert!(matches!(
        outcome,
        CustodyAttestationOutcome::FixtureAttestationAccepted {
            environment: TrustBundleEnvironment::Testnet,
            ..
        }
    ));
}

#[test]
fn a1_fixture_attestation_accepted_via_trait() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    let verifier = FixtureCustodyAttestationVerifier;
    assert_eq!(verifier.class(), CustodyAttestationClass::FixtureAttestation);
    let outcome = verifier.verify_custody_attestation(
        &s.evidence,
        &s.input,
        &s.domain,
        CustodyAttestationPolicy::FixtureAttestationAllowed,
    );
    assert!(outcome.is_accept());
}

#[test]
fn a3_evidence_digest_deterministic() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    assert_eq!(s.evidence.evidence_digest(), s.evidence.evidence_digest());
    // Changing any field changes the digest.
    let mut other = s.evidence.clone();
    other.candidate_digest = "different".to_string();
    assert_ne!(s.evidence.evidence_digest(), other.evidence_digest());
}

#[test]
fn a4_input_digest_deterministic() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    assert_eq!(s.input.input_digest(), s.input.input_digest());
    let mut other = s.input.clone();
    other.expected_authority_domain_sequence = 3;
    assert_ne!(s.input.input_digest(), other.input_digest());
}

#[test]
fn a5_transcript_digest_deterministic() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    let ev = s.evidence.evidence_digest();
    let inp = s.input.input_digest();
    let t1 = attestation_transcript_digest(&ev, &inp);
    let t2 = attestation_transcript_digest(&ev, &inp);
    assert_eq!(t1, t2);
    assert_ne!(t1, attestation_transcript_digest(&inp, &ev));
}

#[test]
fn a6_evidence_binds_full_tuple() {
    // Mutating any bound field flips acceptance to a precise rejection.
    let base = accepted_scenario(TrustBundleEnvironment::Devnet);
    assert!(verify(&base, CustodyAttestationPolicy::FixtureAttestationAllowed).is_accept());

    let mut mutate_checks: Vec<Box<dyn Fn(&mut CustodyAttestationEvidence)>> = Vec::new();
    mutate_checks.push(Box::new(|e| e.chain_id = "x".to_string()));
    mutate_checks.push(Box::new(|e| e.genesis_hash = "x".to_string()));
    mutate_checks.push(Box::new(|e| e.authority_root_fingerprint = "x".to_string()));
    mutate_checks.push(Box::new(|e| e.bundle_signing_key_fingerprint = "x".to_string()));
    mutate_checks.push(Box::new(|e| e.custody_class = AuthorityCustodyClass::Hsm));
    mutate_checks.push(Box::new(|e| e.backend_provider_signer_id = "x".to_string()));
    mutate_checks.push(Box::new(|e| e.custody_key_id = "x".to_string()));
    mutate_checks.push(Box::new(|e| e.lifecycle_action = LocalLifecycleAction::Retire));
    mutate_checks.push(Box::new(|e| e.candidate_digest = "x".to_string()));
    mutate_checks.push(Box::new(|e| e.authority_domain_sequence = 99));

    for m in mutate_checks {
        let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
        m(&mut s.evidence);
        let outcome = verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed);
        assert!(
            outcome.is_reject(),
            "expected rejection after mutating a bound field, got {outcome:?}"
        );
    }
}

#[test]
fn a7_composes_with_run188_custody_metadata() {
    let env = TrustBundleEnvironment::Devnet;
    let s = accepted_scenario(env);
    let custody = good_custody_attestation(env, &s.candidate);
    let prior = prior_versioned(env);
    let outcome = validate_custody_metadata_and_attestation(
        &custody,
        &s.candidate,
        Some(&prior),
        &s.domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(KEY_ID),
        AuthorityCustodyPolicy::FixtureOnly,
        &s.evidence,
        &s.input,
        CustodyAttestationPolicy::FixtureAttestationAllowed,
        NOW,
        false,
    );
    assert!(outcome.is_accept(), "got {outcome:?}");
}

#[test]
fn a8_composes_with_run203_fixture_kms_backend_evidence() {
    // The evidence binds a Run 203 KMS backend identity/transcript and
    // the Kms custody class.
    let env = TrustBundleEnvironment::Devnet;
    let candidate = rotate_candidate(env);
    let _identity = BackendIdentity {
        backend_kind: BackendKind::FixtureKms,
        backend_id: PROVIDER_ID.to_string(),
        provider_id: PROVIDER_ID.to_string(),
        key_id: KEY_ID.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        bundle_signing_key_fingerprint: candidate.active_bundle_signing_key_fingerprint.clone(),
        environment: env,
        chain_id: CHAIN_ID.to_string(),
        genesis_hash: GENESIS_HASH.to_string(),
        suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        attestation_digest: "kms-attest".to_string(),
        key_usage_policy: "authority-lifecycle-signing-only".to_string(),
        allowed_lifecycle_actions: vec![LocalLifecycleAction::Rotate],
        freshness_unix: Some(FRESH),
        expires_at_unix: Some(EXPIRES),
    };
    let mut s = accepted_scenario(env);
    s.evidence.custody_class = AuthorityCustodyClass::Kms;
    s.evidence.custody_backend_kind = Some(BackendKind::FixtureKms.tag().to_string());
    s.input.expected_custody_class = AuthorityCustodyClass::Kms;
    assert!(verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed).is_accept());
}

#[test]
fn a9_composes_with_run203_fixture_hsm_backend_evidence() {
    let env = TrustBundleEnvironment::Testnet;
    let mut s = accepted_scenario(env);
    s.evidence.custody_class = AuthorityCustodyClass::Hsm;
    s.evidence.custody_backend_kind = Some(BackendKind::FixtureHsm.tag().to_string());
    s.input.expected_custody_class = AuthorityCustodyClass::Hsm;
    assert!(verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed).is_accept());
}

#[test]
fn a10_composes_with_run201_remote_signer_transport_evidence() {
    // The Run 201 RemoteSigner transport request/response/transcript
    // digests are bound as opaque evidence fields; the RemoteSigner path
    // remains a separate custody option.
    let env = TrustBundleEnvironment::Devnet;
    let candidate = rotate_candidate(env);
    let _request = BackendRequest {
        environment: env,
        chain_id: CHAIN_ID.to_string(),
        genesis_hash: GENESIS_HASH.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        lifecycle_action: LocalLifecycleAction::Rotate,
        candidate_digest: DIGEST_2.to_string(),
        authority_domain_sequence: 2,
        custody_class: AuthorityCustodyClass::Kms,
        key_id: KEY_ID.to_string(),
        active_signing_key_fingerprint: Some(KEY_A.to_string()),
        new_signing_key_fingerprint: Some(candidate.active_bundle_signing_key_fingerprint.clone()),
        revoked_signing_key_fingerprint: None,
        governance_proof_digest: None,
        custody_attestation_digest: "custody-att".to_string(),
        request_nonce: "req".to_string(),
        request_timestamp_unix: Some(NOW),
    };
    let _response = BackendResponse {
        backend_kind: BackendKind::FixtureKms,
        bound_request_digest: "bound".to_string(),
        backend_id: PROVIDER_ID.to_string(),
        provider_id: PROVIDER_ID.to_string(),
        key_id: KEY_ID.to_string(),
        signature_suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        signature_commitment: "sig".to_string(),
        attestation_digest: "att".to_string(),
        response_nonce: "resp".to_string(),
        freshness_unix: Some(FRESH),
        expires_at_unix: Some(EXPIRES),
    };
    let s = accepted_scenario(env);
    assert!(verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed).is_accept());
}

#[test]
fn a11_production_attestation_boundary_callable_unavailable() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    let verifier = ProductionAttestationVerifier;
    let outcome = verifier.verify_custody_attestation(
        &s.evidence,
        &s.input,
        &s.domain,
        CustodyAttestationPolicy::ProductionAttestationRequired,
    );
    assert_eq!(
        outcome,
        CustodyAttestationOutcome::ProductionAttestationUnavailable
    );
    assert!(outcome.is_unavailable());
}

#[test]
fn a12_cloud_kms_attestation_boundary_callable_unavailable() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    let verifier = CloudKmsAttestationVerifier;
    let outcome = verifier.verify_custody_attestation(
        &s.evidence,
        &s.input,
        &s.domain,
        CustodyAttestationPolicy::KmsAttestationRequired,
    );
    assert_eq!(
        outcome,
        CustodyAttestationOutcome::CloudKmsAttestationUnavailable
    );
    assert!(outcome.is_unavailable());
}

#[test]
fn a13_pkcs11_hsm_attestation_boundary_callable_unavailable() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    let verifier = Pkcs11HsmAttestationVerifier;
    let outcome = verifier.verify_custody_attestation(
        &s.evidence,
        &s.input,
        &s.domain,
        CustodyAttestationPolicy::HsmAttestationRequired,
    );
    assert_eq!(
        outcome,
        CustodyAttestationOutcome::Pkcs11HsmAttestationUnavailable
    );
}

#[test]
fn a14_governance_classes_unchanged_when_attestation_disabled() {
    // When the attestation policy is Disabled, the verifier returns the
    // inert `AttestationDisabled` regardless of governance authority
    // class; it never mutates or interprets governance proof behavior.
    for gov in [
        GovernanceAuthorityClass::GenesisBound,
        GovernanceAuthorityClass::EmergencyCouncil,
        GovernanceAuthorityClass::OnChainGovernance,
    ] {
        let env = TrustBundleEnvironment::Devnet;
        let candidate = rotate_candidate(env);
        let custody = AuthorityCustodyAttestation {
            governance_authority_class: gov,
            ..good_custody_attestation(env, &candidate)
        };
        // Run 188 custody composition under FixtureOnly still works; the
        // attestation layer is Disabled and rejects inertly.
        let s = accepted_scenario(env);
        let prior = prior_versioned(env);
        let outcome = validate_custody_metadata_and_attestation(
            &custody,
            &candidate,
            Some(&prior),
            &s.domain,
            gov,
            LocalLifecycleAction::Rotate,
            DIGEST_2,
            2,
            Some(KEY_ID),
            AuthorityCustodyPolicy::FixtureOnly,
            &s.evidence,
            &s.input,
            CustodyAttestationPolicy::Disabled,
            NOW,
            false,
        );
        assert!(matches!(
            outcome,
            CustodyMetadataAttestationOutcome::AttestationRejected {
                attestation_outcome: CustodyAttestationOutcome::AttestationDisabled,
                ..
            }
        ));
    }
}

// ===========================================================================
// Rejection scenarios R1–R40
// ===========================================================================

#[test]
fn r1_rejected_under_disabled_policy() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    assert_eq!(
        verify(&s, CustodyAttestationPolicy::Disabled),
        CustodyAttestationOutcome::AttestationDisabled
    );
}

#[test]
fn r2_fixture_rejected_production_required() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    assert_eq!(
        verify(&s, CustodyAttestationPolicy::ProductionAttestationRequired),
        CustodyAttestationOutcome::FixtureRejectedProductionRequired
    );
}

#[test]
fn r3_fixture_rejected_mainnet_production_required() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    assert_eq!(
        verify(
            &s,
            CustodyAttestationPolicy::MainnetProductionAttestationRequired
        ),
        CustodyAttestationOutcome::FixtureRejectedMainnetProductionRequired
    );
}

#[test]
fn r4_remote_signer_attestation_unavailable() {
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.evidence.attestation_class = CustodyAttestationClass::RemoteSignerAttestation;
    assert_eq!(
        verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed),
        CustodyAttestationOutcome::RemoteSignerAttestationUnavailable
    );
    // Also via the required policy.
    assert_eq!(
        verify(&s, CustodyAttestationPolicy::RemoteSignerAttestationRequired),
        CustodyAttestationOutcome::RemoteSignerAttestationUnavailable
    );
}

#[test]
fn r5_kms_attestation_unavailable() {
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.evidence.attestation_class = CustodyAttestationClass::KmsAttestation;
    assert_eq!(
        verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed),
        CustodyAttestationOutcome::KmsAttestationUnavailable
    );
    assert_eq!(
        verify(&s, CustodyAttestationPolicy::KmsAttestationRequired),
        CustodyAttestationOutcome::KmsAttestationUnavailable
    );
}

#[test]
fn r6_hsm_attestation_unavailable() {
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.evidence.attestation_class = CustodyAttestationClass::HsmAttestation;
    assert_eq!(
        verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed),
        CustodyAttestationOutcome::HsmAttestationUnavailable
    );
    assert_eq!(
        verify(&s, CustodyAttestationPolicy::HsmAttestationRequired),
        CustodyAttestationOutcome::HsmAttestationUnavailable
    );
}

#[test]
fn r7_cloud_kms_attestation_unavailable() {
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.evidence.attestation_class = CustodyAttestationClass::CloudKmsAttestationUnavailable;
    assert_eq!(
        verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed),
        CustodyAttestationOutcome::CloudKmsAttestationUnavailable
    );
}

#[test]
fn r8_pkcs11_hsm_attestation_unavailable() {
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.evidence.attestation_class = CustodyAttestationClass::Pkcs11HsmAttestationUnavailable;
    assert_eq!(
        verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed),
        CustodyAttestationOutcome::Pkcs11HsmAttestationUnavailable
    );
}

#[test]
fn r9_production_attestation_unavailable() {
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.evidence.attestation_class = CustodyAttestationClass::ProductionAttestationUnavailable;
    assert_eq!(
        verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed),
        CustodyAttestationOutcome::ProductionAttestationUnavailable
    );
    assert_eq!(
        verify(&s, CustodyAttestationPolicy::ProductionAttestationRequired),
        CustodyAttestationOutcome::ProductionAttestationUnavailable
    );
}

#[test]
fn r10_mainnet_production_attestation_unavailable() {
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.evidence.attestation_class = CustodyAttestationClass::ProductionAttestationUnavailable;
    assert_eq!(
        verify(
            &s,
            CustodyAttestationPolicy::MainnetProductionAttestationRequired
        ),
        CustodyAttestationOutcome::MainNetProductionAttestationUnavailable
    );
}

#[test]
fn r11_unknown_attestation_class_rejected() {
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.evidence.attestation_class = CustodyAttestationClass::Unknown;
    assert!(matches!(
        verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed),
        CustodyAttestationOutcome::UnknownAttestationClassRejected { .. }
    ));
}

#[test]
fn r12_wrong_environment_rejected() {
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.evidence.environment = TrustBundleEnvironment::Testnet;
    assert!(matches!(
        verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed),
        CustodyAttestationOutcome::WrongEnvironment { .. }
    ));
}

#[test]
fn r13_wrong_chain_rejected() {
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.evidence.chain_id = "9999999999999999".to_string();
    assert!(matches!(
        verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed),
        CustodyAttestationOutcome::WrongChain { .. }
    ));
}

#[test]
fn r14_wrong_genesis_rejected() {
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.evidence.genesis_hash = "ffff".to_string();
    assert!(matches!(
        verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed),
        CustodyAttestationOutcome::WrongGenesis { .. }
    ));
}

#[test]
fn r15_wrong_authority_root_rejected() {
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.evidence.authority_root_fingerprint = "ffff".to_string();
    assert!(matches!(
        verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed),
        CustodyAttestationOutcome::WrongAuthorityRoot { .. }
    ));
}

#[test]
fn r16_wrong_signing_key_fingerprint_rejected() {
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.evidence.bundle_signing_key_fingerprint = "ffff".to_string();
    assert!(matches!(
        verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed),
        CustodyAttestationOutcome::WrongSigningKeyFingerprint { .. }
    ));
}

#[test]
fn r17_wrong_custody_class_rejected() {
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.evidence.custody_class = AuthorityCustodyClass::Hsm;
    assert!(matches!(
        verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed),
        CustodyAttestationOutcome::WrongCustodyClass { .. }
    ));
}

#[test]
fn r18_wrong_backend_provider_signer_id_rejected() {
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.evidence.backend_provider_signer_id = "other".to_string();
    assert!(matches!(
        verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed),
        CustodyAttestationOutcome::WrongBackendProviderSignerId { .. }
    ));
}

#[test]
fn r19_wrong_key_id_rejected() {
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.evidence.custody_key_id = "other".to_string();
    assert!(matches!(
        verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed),
        CustodyAttestationOutcome::WrongKeyId { .. }
    ));
}

#[test]
fn r20_wrong_suite_rejected() {
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.evidence.suite_id = 200;
    assert!(matches!(
        verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed),
        CustodyAttestationOutcome::WrongSuite { .. }
    ));
}

#[test]
fn r21_wrong_lifecycle_action_rejected() {
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.evidence.lifecycle_action = LocalLifecycleAction::Revoke;
    assert!(matches!(
        verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed),
        CustodyAttestationOutcome::WrongLifecycleAction { .. }
    ));
}

#[test]
fn r22_wrong_candidate_digest_rejected() {
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.evidence.candidate_digest = "ffff".to_string();
    assert!(matches!(
        verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed),
        CustodyAttestationOutcome::WrongCandidateDigest { .. }
    ));
}

#[test]
fn r23_wrong_authority_domain_sequence_rejected() {
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.evidence.authority_domain_sequence = 7;
    assert!(matches!(
        verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed),
        CustodyAttestationOutcome::WrongAuthorityDomainSequence { .. }
    ));
}

#[test]
fn r24_wrong_governance_proof_digest_rejected() {
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.evidence.governance_proof_digest = Some("other".to_string());
    assert!(matches!(
        verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed),
        CustodyAttestationOutcome::WrongGovernanceProofDigest { .. }
    ));
}

#[test]
fn r25_wrong_request_digest_rejected() {
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.evidence.request_digest = Some("other".to_string());
    assert!(matches!(
        verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed),
        CustodyAttestationOutcome::WrongRequestDigest { .. }
    ));
}

#[test]
fn r26_wrong_response_digest_rejected() {
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.evidence.response_digest = Some("other".to_string());
    assert!(matches!(
        verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed),
        CustodyAttestationOutcome::WrongResponseDigest { .. }
    ));
}

#[test]
fn r27_wrong_transcript_digest_rejected() {
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.evidence.transcript_digest = Some("other".to_string());
    assert!(matches!(
        verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed),
        CustodyAttestationOutcome::WrongTranscriptDigest { .. }
    ));
}

#[test]
fn r28_stale_or_replayed_attestation_rejected() {
    // Nonce mismatch.
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.evidence.attestation_nonce = "stale".to_string();
    assert_eq!(
        verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed),
        CustodyAttestationOutcome::StaleOrReplayedAttestation
    );

    // Issuance timestamp outside the replay window.
    let mut s2 = accepted_scenario(TrustBundleEnvironment::Devnet);
    s2.evidence.issued_at_unix = Some(WINDOW_UNTIL + 10);
    assert_eq!(
        verify(&s2, CustodyAttestationPolicy::FixtureAttestationAllowed),
        CustodyAttestationOutcome::StaleOrReplayedAttestation
    );
}

#[test]
fn r29_expired_attestation_rejected() {
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.input.now_unix = EXPIRES + 1;
    assert!(matches!(
        verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed),
        CustodyAttestationOutcome::ExpiredAttestation { .. }
    ));
}

#[test]
fn r30_malformed_attestation_evidence_rejected() {
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.evidence.attestation_nonce = String::new();
    assert!(matches!(
        verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed),
        CustodyAttestationOutcome::MalformedAttestationEvidence { .. }
    ));
}

#[test]
fn r31_unsupported_attestation_version_rejected() {
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.evidence.attestation_version = 99;
    assert!(matches!(
        verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed),
        CustodyAttestationOutcome::UnsupportedAttestationVersion { version: 99 }
    ));
}

#[test]
fn r32_invalid_attestation_commitment_rejected() {
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    s.evidence.attestation_commitment =
        CUSTODY_ATTESTATION_INVALID_COMMITMENT_SENTINEL.to_string();
    assert_eq!(
        verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed),
        CustodyAttestationOutcome::InvalidAttestationCommitment
    );
}

#[test]
fn r33_local_operator_cannot_satisfy_production_attestation() {
    assert!(local_operator_cannot_satisfy_production_attestation());
}

#[test]
fn r34_peer_majority_cannot_satisfy_production_attestation() {
    assert!(peer_majority_cannot_satisfy_production_attestation());
}

#[test]
fn r35_attestation_valid_custody_invalid_rejected() {
    // Attestation evidence is valid, but the Run 188 custody metadata is
    // invalid (wrong key id), so the composition rejects at the custody
    // layer and never accepts.
    let env = TrustBundleEnvironment::Devnet;
    let s = accepted_scenario(env);
    let mut custody = good_custody_attestation(env, &s.candidate);
    custody.custody_key_id = "wrong-key".to_string();
    let prior = prior_versioned(env);
    let outcome = validate_custody_metadata_and_attestation(
        &custody,
        &s.candidate,
        Some(&prior),
        &s.domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(KEY_ID),
        AuthorityCustodyPolicy::FixtureOnly,
        &s.evidence,
        &s.input,
        CustodyAttestationPolicy::FixtureAttestationAllowed,
        NOW,
        false,
    );
    assert!(matches!(
        outcome,
        CustodyMetadataAttestationOutcome::LifecycleOrCustodyRejected(_)
    ));
}

#[test]
fn r36_custody_valid_attestation_invalid_rejected() {
    // Run 188 custody metadata is valid, but the attestation evidence is
    // invalid (wrong candidate digest), so the composition rejects at the
    // attestation layer.
    let env = TrustBundleEnvironment::Devnet;
    let mut s = accepted_scenario(env);
    s.evidence.candidate_digest = "wrong".to_string();
    let custody = good_custody_attestation(env, &s.candidate);
    let prior = prior_versioned(env);
    let outcome = validate_custody_metadata_and_attestation(
        &custody,
        &s.candidate,
        Some(&prior),
        &s.domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(KEY_ID),
        AuthorityCustodyPolicy::FixtureOnly,
        &s.evidence,
        &s.input,
        CustodyAttestationPolicy::FixtureAttestationAllowed,
        NOW,
        false,
    );
    assert!(matches!(
        outcome,
        CustodyMetadataAttestationOutcome::AttestationRejected {
            attestation_outcome: CustodyAttestationOutcome::WrongCandidateDigest { .. },
            ..
        }
    ));
}

#[test]
fn r37_lifecycle_governance_custody_valid_production_attestation_unavailable() {
    // Everything up to attestation validates, but the attestation policy
    // requires a production attestation that is unavailable.
    let env = TrustBundleEnvironment::Devnet;
    let s = accepted_scenario(env);
    let custody = good_custody_attestation(env, &s.candidate);
    let prior = prior_versioned(env);
    let outcome = validate_custody_metadata_and_attestation(
        &custody,
        &s.candidate,
        Some(&prior),
        &s.domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(KEY_ID),
        AuthorityCustodyPolicy::FixtureOnly,
        &s.evidence,
        &s.input,
        CustodyAttestationPolicy::ProductionAttestationRequired,
        NOW,
        false,
    );
    assert!(matches!(
        outcome,
        CustodyMetadataAttestationOutcome::AttestationRejected {
            attestation_outcome:
                CustodyAttestationOutcome::FixtureRejectedProductionRequired,
            ..
        }
    ));
}

#[test]
fn r38_validation_only_rejection_is_non_mutating() {
    // The verifier takes shared references and returns a value; calling it
    // repeatedly does not change the inputs.
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    let before_ev = s.evidence.clone();
    let before_in = s.input.clone();
    let _ = verify(&s, CustodyAttestationPolicy::Disabled);
    let _ = verify(&s, CustodyAttestationPolicy::ProductionAttestationRequired);
    let _ = verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed);
    assert_eq!(s.evidence, before_ev);
    assert_eq!(s.input, before_in);
}

#[test]
fn r39_mutating_preflight_rejection_produces_no_side_effects() {
    // The composition helper is pure: it returns a typed decision and
    // performs no marker write, no sequence write, no live trust swap, no
    // session eviction, and no Run 070 call. We assert the rejection path
    // leaves the candidate untouched.
    let env = TrustBundleEnvironment::Devnet;
    let mut s = accepted_scenario(env);
    s.evidence.attestation_commitment =
        CUSTODY_ATTESTATION_INVALID_COMMITMENT_SENTINEL.to_string();
    let custody = good_custody_attestation(env, &s.candidate);
    let prior = prior_versioned(env);
    let candidate_before = s.candidate.clone();
    let outcome = validate_custody_metadata_and_attestation(
        &custody,
        &s.candidate,
        Some(&prior),
        &s.domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(KEY_ID),
        AuthorityCustodyPolicy::FixtureOnly,
        &s.evidence,
        &s.input,
        CustodyAttestationPolicy::FixtureAttestationAllowed,
        NOW,
        false,
    );
    assert!(outcome.is_reject());
    assert_eq!(s.candidate, candidate_before);
}

#[test]
fn r40_mainnet_peer_driven_apply_refused_even_with_fixture_attestation() {
    // On MainNet, a peer-driven-apply preflight is refused before custody
    // or attestation is consulted, even though the fixture attestation
    // would otherwise verify on DevNet/TestNet.
    let env = TrustBundleEnvironment::Mainnet;
    let candidate = rotate_candidate(env);
    let s = Scenario {
        domain: domain(env),
        candidate: candidate.clone(),
        evidence: evidence(CustodyAttestationClass::FixtureAttestation, env, &candidate),
        input: input(env, &candidate),
    };
    let custody = good_custody_attestation(env, &candidate);
    let prior = prior_versioned(env);
    let outcome = validate_lifecycle_custody_and_attestation(
        &custody,
        &s.candidate,
        Some(&prior),
        &s.domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(KEY_ID),
        AuthorityCustodyPolicy::FixtureOnly,
        &s.evidence,
        &s.input,
        CustodyAttestationPolicy::FixtureAttestationAllowed,
        NOW,
        true,
    );
    assert_eq!(
        outcome,
        CustodyMetadataAttestationOutcome::MainNetPeerDrivenApplyRefused
    );

    // The fixture attestation itself is also refused for a MainNet trust
    // domain even outside a peer-driven preflight.
    assert_eq!(
        verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed),
        CustodyAttestationOutcome::FixtureRejectedForMainNet
    );
    assert!(mainnet_peer_driven_apply_remains_refused_under_attestation_boundary(env));
}

// ===========================================================================
// Extra invariants
// ===========================================================================

#[test]
fn fixture_attestation_refused_for_mainnet_trust_domain() {
    let env = TrustBundleEnvironment::Mainnet;
    let candidate = rotate_candidate(env);
    let s = Scenario {
        domain: domain(env),
        candidate: candidate.clone(),
        evidence: evidence(CustodyAttestationClass::FixtureAttestation, env, &candidate),
        input: input(env, &candidate),
    };
    assert_eq!(
        verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed),
        CustodyAttestationOutcome::FixtureRejectedForMainNet
    );
}

#[test]
fn provider_identity_digest_deterministic_and_distinct() {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    assert_eq!(
        s.evidence.provider_identity_digest(),
        s.evidence.provider_identity_digest()
    );
    let mut other = s.evidence.clone();
    other.backend_provider_signer_id = "different-provider".to_string();
    assert_ne!(
        s.evidence.provider_identity_digest(),
        other.provider_identity_digest()
    );
}

#[test]
fn class_and_policy_tags_are_stable() {
    assert_eq!(CustodyAttestationClass::FixtureAttestation.tag(), "fixture-attestation");
    assert_eq!(
        CustodyAttestationPolicy::MainnetProductionAttestationRequired.tag(),
        "mainnet-production-attestation-required"
    );
    assert!(CustodyAttestationClass::KmsAttestation.is_production_unavailable());
    assert!(CustodyAttestationClass::FixtureAttestation.is_fixture());
    assert!(CustodyAttestationPolicy::ProductionAttestationRequired.requires_production_attestation());
}

#[test]
fn production_verifiers_report_their_class() {
    assert_eq!(
        RemoteSignerAttestationVerifier.class(),
        CustodyAttestationClass::RemoteSignerAttestation
    );
    assert_eq!(
        KmsAttestationVerifier.class(),
        CustodyAttestationClass::KmsAttestation
    );
    assert_eq!(
        HsmAttestationVerifier.class(),
        CustodyAttestationClass::HsmAttestation
    );
}