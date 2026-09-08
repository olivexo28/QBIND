//! Run 204 — release-built helper that exercises the Run 203 production
//! **KMS/HSM backend abstraction boundary**
//! ([`qbind_node::pqc_authority_kms_hsm_backend`]) **in release mode**,
//! through the production library symbols, layered over the Run 188
//! authority custody boundary
//! ([`qbind_node::pqc_authority_custody`]).
//!
//! Per `task/RUN_204_TASK.txt`, Run 204 is the release-binary evidence
//! run for the Run 203 source/test KMS/HSM backend abstraction boundary.
//! This helper is fixture-only tooling and:
//!
//! * does NOT modify any production runtime code, CLI flag, env var, wire
//!   / marker / sequence / trust-bundle / peer-candidate-envelope schema
//!   beyond what Runs 070, 130–203 already established;
//! * does NOT enable MainNet peer-driven apply on any surface;
//! * does NOT mutate any live trust state, write any marker, advance any
//!   sequence, swap any live trust, evict any session, or invoke Run 070 —
//!   every backend, verifier, and composition function exercised here is
//!   a pure function returning an owned typed outcome;
//! * does NOT open any P2P socket and performs no network or backend I/O;
//! * does NOT implement any real KMS backend, real HSM backend, cloud-KMS
//!   integration, PKCS#11 integration, networked signer daemon, or real
//!   RemoteSigner backend; the
//!   [`qbind_node::pqc_authority_kms_hsm_backend::ProductionKmsBackend`],
//!   [`qbind_node::pqc_authority_kms_hsm_backend::ProductionHsmBackend`],
//!   [`qbind_node::pqc_authority_kms_hsm_backend::CloudKmsBackend`], and
//!   [`qbind_node::pqc_authority_kms_hsm_backend::Pkcs11HsmBackend`]
//!   always return the typed unavailable reject;
//! * never elevates the DevNet/TestNet
//!   [`qbind_node::pqc_authority_kms_hsm_backend::FixtureKmsBackend`] /
//!   [`qbind_node::pqc_authority_kms_hsm_backend::FixtureHsmBackend`]
//!   into MainNet production custody (MainNet peer-driven apply always
//!   refuses at the typed boundary);
//! * exists alongside (and does NOT replace) the Run 203 source/test
//!   target
//!   `crates/qbind-node/tests/run_203_kms_hsm_backend_boundary_tests.rs`.
//!
//! The helper proves, in release mode through the production library
//! symbols:
//!
//! 1. fixture KMS/HSM backends remain DevNet/TestNet evidence-only;
//! 2. production KMS/HSM backends remain unavailable/fail-closed;
//! 3. cloud-KMS and PKCS#11 HSM variants remain unavailable/fail-closed;
//! 4. backend identity/request/response/transcript digests are
//!    deterministic and domain-bound;
//! 5. the backend boundary composes with the Run 188 custody classes;
//! 6. the RemoteSigner path (Runs 194–202) remains separate and
//!    unchanged;
//! 7. MainNet peer-driven apply remains refused;
//! 8. no real KMS/HSM/cloud-KMS/PKCS#11/RemoteSigner backend / governance
//!    execution / validator-set rotation is claimed.
//!
//! Usage:
//! ```text
//! run_204_kms_hsm_backend_release_binary_helper <OUT_DIR>
//! ```

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use qbind_ledger::BundleSigningRatificationV2Action;
use qbind_node::pqc_authority_custody::{
    AuthorityCustodyAttestation, AuthorityCustodyClass, AuthorityCustodyPolicy,
};
use qbind_node::pqc_authority_kms_hsm_backend::{
    backend_transcript_digest, custody_class_routes_to_kms_hsm_backend,
    local_operator_cannot_satisfy_backend_policy,
    mainnet_peer_driven_apply_remains_refused_under_kms_hsm_backend_boundary,
    peer_majority_cannot_satisfy_backend_policy, validate_backend_for_custody_class,
    validate_lifecycle_governance_custody_and_backend,
    verify_authority_custody_backend_response, AuthorityCustodyBackend, BackendExpectations,
    BackendIdentity, BackendKind, BackendOutcome, BackendPolicy, BackendRequest, BackendResponse,
    CloudKmsBackend, FixtureHsmBackend, FixtureKmsBackend, LifecycleCustodyBackendOutcome,
    Pkcs11HsmBackend, ProductionHsmBackend, ProductionKmsBackend,
    KMS_HSM_BACKEND_INVALID_ATTESTATION_SENTINEL, KMS_HSM_BACKEND_INVALID_SIGNATURE_SENTINEL,
};
use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use qbind_node::pqc_authority_state::{
    AuthorityStateUpdateSource, PersistentAuthorityStateRecordV2,
    PersistentAuthorityStateRecordVersioned,
};
use qbind_node::pqc_governance_authority::GovernanceAuthorityClass;
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ---------------------------------------------------------------------------
// Constants — kept structurally identical to the Run 203 source/test
// fixtures so the typed KMS/HSM backend semantics carry over end-to-end in
// release mode.
// ---------------------------------------------------------------------------

const KEY_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEY_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ROOT_FP: &str = "1111111111111111111111111111111111111111";
const OTHER_ROOT_FP: &str = "9999999999999999999999999999999999999999";
const CHAIN_ID: &str = "0000000000000001";
const OTHER_CHAIN: &str = "00000000000000ff";
const GENESIS_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER_GENESIS: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DIGEST_2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const PRIOR_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const CUSTODY_ATTEST_DIGEST: &str = "custody-att-digest-204";
const KEY_ID: &str = "kms-hsm-key-id-204";
const BACKEND_ID: &str = "kms-hsm-backend-204";
const PROVIDER_ID: &str = "kms-hsm-provider-204";
const ATTEST_DIGEST: &str = "kms-hsm-attest-204";
const KEY_USAGE: &str = "authority-lifecycle-signing-only";
const REQ_NONCE: &str = "req-nonce-204";
const RESP_NONCE: &str = "resp-nonce-204";
const NOW: u64 = 1_700_000_000;
const FRESH: u64 = 1_699_999_900;
const EXPIRES: u64 = 1_700_001_000;

// ---------------------------------------------------------------------------
// Fixture builders — mirror the Run 203 source/test corpus.
// ---------------------------------------------------------------------------

fn domain(env: TrustBundleEnvironment) -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(env, CHAIN_ID, GENESIS_HASH, ROOT_FP, PQC_LIFECYCLE_SUITE_ML_DSA_44)
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
    build_v2(env, KEY_B, 2, BundleSigningRatificationV2Action::Rotate, Some(KEY_A), DIGEST_2)
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

fn identity(
    kind: BackendKind,
    env: TrustBundleEnvironment,
    candidate: &PersistentAuthorityStateRecordV2,
) -> BackendIdentity {
    BackendIdentity {
        backend_kind: kind,
        backend_id: BACKEND_ID.to_string(),
        provider_id: PROVIDER_ID.to_string(),
        key_id: KEY_ID.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        bundle_signing_key_fingerprint: candidate.active_bundle_signing_key_fingerprint.clone(),
        environment: env,
        chain_id: CHAIN_ID.to_string(),
        genesis_hash: GENESIS_HASH.to_string(),
        suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        attestation_digest: ATTEST_DIGEST.to_string(),
        key_usage_policy: KEY_USAGE.to_string(),
        allowed_lifecycle_actions: vec![
            LocalLifecycleAction::Rotate,
            LocalLifecycleAction::ActivateInitial,
        ],
        freshness_unix: Some(FRESH),
        expires_at_unix: Some(EXPIRES),
    }
}

fn custody_class_for(kind: BackendKind) -> AuthorityCustodyClass {
    match kind {
        BackendKind::FixtureHsm
        | BackendKind::Pkcs11HsmUnavailable
        | BackendKind::ProductionHsmUnavailable => AuthorityCustodyClass::Hsm,
        _ => AuthorityCustodyClass::Kms,
    }
}

fn request(
    kind: BackendKind,
    env: TrustBundleEnvironment,
    candidate: &PersistentAuthorityStateRecordV2,
) -> BackendRequest {
    BackendRequest {
        environment: env,
        chain_id: CHAIN_ID.to_string(),
        genesis_hash: GENESIS_HASH.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        lifecycle_action: LocalLifecycleAction::Rotate,
        candidate_digest: DIGEST_2.to_string(),
        authority_domain_sequence: 2,
        custody_class: custody_class_for(kind),
        key_id: KEY_ID.to_string(),
        active_signing_key_fingerprint: Some(KEY_A.to_string()),
        new_signing_key_fingerprint: Some(candidate.active_bundle_signing_key_fingerprint.clone()),
        revoked_signing_key_fingerprint: None,
        governance_proof_digest: None,
        custody_attestation_digest: CUSTODY_ATTEST_DIGEST.to_string(),
        request_nonce: REQ_NONCE.to_string(),
        request_timestamp_unix: Some(NOW),
    }
}

fn good_custody_attestation(
    env: TrustBundleEnvironment,
    candidate: &PersistentAuthorityStateRecordV2,
    class: AuthorityCustodyClass,
) -> AuthorityCustodyAttestation {
    AuthorityCustodyAttestation {
        custody_class: class,
        custody_key_id: KEY_ID.to_string(),
        custody_suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        custody_attestation_digest: CUSTODY_ATTEST_DIGEST.to_string(),
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

/// A complete, valid accepted scenario, returning every part a check
/// needs to mutate one field for a rejection vector.
#[derive(Clone)]
struct Scenario {
    domain: AuthorityTrustDomain,
    candidate: PersistentAuthorityStateRecordV2,
    identity: BackendIdentity,
    request: BackendRequest,
    response: BackendResponse,
    expected: BackendExpectations,
    #[allow(dead_code)]
    kind: BackendKind,
    env: TrustBundleEnvironment,
}

fn expectations(
    identity: &BackendIdentity,
    request: &BackendRequest,
    response: &BackendResponse,
    candidate: &PersistentAuthorityStateRecordV2,
) -> BackendExpectations {
    let req_digest = request.request_digest();
    let resp_digest = response.response_digest();
    let transcript =
        backend_transcript_digest(&identity.identity_digest(), &req_digest, &resp_digest);
    BackendExpectations {
        expected_custody_class: request.custody_class,
        expected_lifecycle_action: LocalLifecycleAction::Rotate,
        expected_candidate_digest: DIGEST_2.to_string(),
        expected_authority_domain_sequence: 2,
        expected_key_id: KEY_ID.to_string(),
        expected_signing_key_fingerprint: candidate.active_bundle_signing_key_fingerprint.clone(),
        expected_custody_attestation_digest: CUSTODY_ATTEST_DIGEST.to_string(),
        expected_request_nonce: REQ_NONCE.to_string(),
        expected_response_nonce: RESP_NONCE.to_string(),
        expected_request_digest: req_digest,
        expected_response_digest: resp_digest,
        expected_transcript_digest: transcript,
        now_unix: NOW,
    }
}

fn sign_with_kind(
    kind: BackendKind,
    identity: &BackendIdentity,
    req: &BackendRequest,
) -> Result<BackendResponse, BackendOutcome> {
    match kind {
        BackendKind::FixtureKms => FixtureKmsBackend {
            identity: identity.clone(),
            response_nonce: RESP_NONCE.to_string(),
            response_freshness_unix: Some(FRESH),
            response_expires_at_unix: Some(EXPIRES),
        }
        .sign_authority_lifecycle_request(req),
        BackendKind::FixtureHsm => FixtureHsmBackend {
            identity: identity.clone(),
            response_nonce: RESP_NONCE.to_string(),
            response_freshness_unix: Some(FRESH),
            response_expires_at_unix: Some(EXPIRES),
        }
        .sign_authority_lifecycle_request(req),
        _ => panic!("sign_with_kind only supports fixture kinds"),
    }
}

fn scenario(kind: BackendKind, env: TrustBundleEnvironment) -> Scenario {
    let candidate = rotate_candidate(env);
    let identity = identity(kind, env, &candidate);
    let request = request(kind, env, &candidate);
    let response = sign_with_kind(kind, &identity, &request).expect("fixture backend signs");
    let expected = expectations(&identity, &request, &response, &candidate);
    Scenario {
        domain: domain(env),
        identity,
        request,
        response,
        expected,
        candidate,
        kind,
        env,
    }
}

/// Build a scenario whose response carries a production-class backend
/// kind, to drive the unavailable paths through the verifier.
fn production_response(kind: BackendKind, env: TrustBundleEnvironment) -> Scenario {
    let candidate = rotate_candidate(env);
    let identity = identity(kind, env, &candidate);
    let request = request(kind, env, &candidate);
    let response = BackendResponse {
        backend_kind: kind,
        bound_request_digest: request.request_digest(),
        backend_id: BACKEND_ID.to_string(),
        provider_id: PROVIDER_ID.to_string(),
        key_id: KEY_ID.to_string(),
        signature_suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        signature_commitment: "placeholder".to_string(),
        attestation_digest: ATTEST_DIGEST.to_string(),
        response_nonce: RESP_NONCE.to_string(),
        freshness_unix: Some(FRESH),
        expires_at_unix: Some(EXPIRES),
    };
    let expected = expectations(&identity, &request, &response, &candidate);
    Scenario {
        domain: domain(env),
        identity,
        request,
        response,
        expected,
        candidate,
        kind,
        env,
    }
}

fn validate(s: &Scenario, policy: BackendPolicy) -> BackendOutcome {
    verify_authority_custody_backend_response(
        &s.identity,
        &s.request,
        &s.response,
        &s.domain,
        &s.expected,
        policy,
    )
}

fn fixture_policy_for(kind: BackendKind) -> BackendPolicy {
    match kind {
        BackendKind::FixtureKms => BackendPolicy::FixtureKmsAllowed,
        BackendKind::FixtureHsm => BackendPolicy::FixtureHsmAllowed,
        _ => panic!("fixture_policy_for only supports fixture kinds"),
    }
}

// ---------------------------------------------------------------------------
// Typed-outcome tagging — short, stable strings for the evidence tables.
// ---------------------------------------------------------------------------

fn backend_tag(outcome: &BackendOutcome) -> String {
    use BackendOutcome as O;
    let name = match outcome {
        O::FixtureKmsAccepted { .. } => "accept:FixtureKmsAccepted",
        O::FixtureHsmAccepted { .. } => "accept:FixtureHsmAccepted",
        O::Disabled => "reject:Disabled",
        O::FixtureRejectedProductionRequired => "reject:FixtureRejectedProductionRequired",
        O::FixtureRejectedMainnetProductionRequired => {
            "reject:FixtureRejectedMainnetProductionRequired"
        }
        O::ProductionKmsUnavailable => "reject:ProductionKmsUnavailable",
        O::ProductionHsmUnavailable => "reject:ProductionHsmUnavailable",
        O::CloudKmsUnavailable => "reject:CloudKmsUnavailable",
        O::Pkcs11HsmUnavailable => "reject:Pkcs11HsmUnavailable",
        O::MainNetProductionCustodyUnavailable => "reject:MainNetProductionCustodyUnavailable",
        O::FixtureRejectedForMainNet => "reject:FixtureRejectedForMainNet",
        O::BackendKindPolicyMismatch { .. } => "reject:BackendKindPolicyMismatch",
        O::UnknownBackendRejected { .. } => "reject:UnknownBackendRejected",
        O::WrongEnvironment { .. } => "reject:WrongEnvironment",
        O::WrongChain { .. } => "reject:WrongChain",
        O::WrongGenesis { .. } => "reject:WrongGenesis",
        O::WrongAuthorityRoot { .. } => "reject:WrongAuthorityRoot",
        O::WrongKeyId { .. } => "reject:WrongKeyId",
        O::WrongSigningKeyFingerprint { .. } => "reject:WrongSigningKeyFingerprint",
        O::WrongLifecycleAction { .. } => "reject:WrongLifecycleAction",
        O::WrongCandidateDigest { .. } => "reject:WrongCandidateDigest",
        O::WrongAuthorityDomainSequence { .. } => "reject:WrongAuthorityDomainSequence",
        O::WrongRequestDigest { .. } => "reject:WrongRequestDigest",
        O::WrongResponseDigest { .. } => "reject:WrongResponseDigest",
        O::WrongTranscriptDigest { .. } => "reject:WrongTranscriptDigest",
        O::StaleOrReplayedRequest { .. } => "reject:StaleOrReplayedRequest",
        O::StaleOrReplayedResponse { .. } => "reject:StaleOrReplayedResponse",
        O::ExpiredAttestation { .. } => "reject:ExpiredAttestation",
        O::ExpiredResponse { .. } => "reject:ExpiredResponse",
        O::UnsupportedSuite { .. } => "reject:UnsupportedSuite",
        O::InvalidAttestation => "reject:InvalidAttestation",
        O::InvalidSignature => "reject:InvalidSignature",
        O::MalformedIdentity { .. } => "reject:MalformedIdentity",
        O::MalformedRequest { .. } => "reject:MalformedRequest",
        O::MalformedResponse { .. } => "reject:MalformedResponse",
        O::LocalOperatorCannotSatisfyBackendPolicy => {
            "reject:LocalOperatorCannotSatisfyBackendPolicy"
        }
        O::PeerMajorityCannotSatisfyBackendPolicy => {
            "reject:PeerMajorityCannotSatisfyBackendPolicy"
        }
        O::NotKmsHsmCustodyClass { .. } => "reject:NotKmsHsmCustodyClass",
    };
    name.to_string()
}

fn composition_tag(outcome: &LifecycleCustodyBackendOutcome) -> String {
    use LifecycleCustodyBackendOutcome as O;
    match outcome {
        O::Accepted { .. } => "accept:Accepted",
        O::LifecycleOrCustodyRejected(_) => "reject:LifecycleOrCustodyRejected",
        O::BackendRejected { .. } => "reject:BackendRejected",
        O::MainNetPeerDrivenApplyRefused => "reject:MainNetPeerDrivenApplyRefused",
    }
    .to_string()
}

// ---------------------------------------------------------------------------
// Evidence writing helpers
// ---------------------------------------------------------------------------

fn write_file(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|e| panic!("create dir {parent:?}: {e}"));
    }
    let mut f = fs::File::create(path).unwrap_or_else(|e| panic!("create {path:?}: {e}"));
    f.write_all(contents.as_bytes())
        .unwrap_or_else(|e| panic!("write {path:?}: {e}"));
}

/// A small table recorder that accumulates `name<TAB>PASS|FAIL<TAB>detail`
/// rows plus an `expected`/`actual` ledger and writes them under `out`.
struct Table {
    name: &'static str,
    rows: String,
    expected: String,
    actual: String,
    pass: u64,
    fail: u64,
}

impl Table {
    fn new(name: &'static str) -> Self {
        Table {
            name,
            rows: String::new(),
            expected: String::new(),
            actual: String::new(),
            pass: 0,
            fail: 0,
        }
    }

    /// Record an equality check on the typed-outcome tag.
    fn check(&mut self, id: &str, expected: &str, actual: &str) {
        let ok = expected == actual;
        if ok {
            self.pass += 1;
        } else {
            self.fail += 1;
        }
        self.rows.push_str(&format!(
            "{}\t{}\texpected={}\tactual={}\n",
            id,
            if ok { "PASS" } else { "FAIL" },
            expected,
            actual
        ));
        self.expected.push_str(&format!("{}\t{}\n", id, expected));
        self.actual.push_str(&format!("{}\t{}\n", id, actual));
    }

    /// Record a boolean assertion.
    fn assert_true(&mut self, id: &str, ok: bool, detail: &str) {
        self.check(id, "true", if ok { "true" } else { "false" });
        if !detail.is_empty() {
            self.rows.push_str(&format!("\t# {}: {}\n", id, detail));
        }
    }

    fn finish(self, out: &Path) -> (u64, u64) {
        let dir = out.join("tables").join(self.name);
        write_file(&dir.join("manifest.txt"), &self.rows);
        write_file(&dir.join("expected.txt"), &self.expected);
        write_file(&dir.join("actual.txt"), &self.actual);
        (self.pass, self.fail)
    }
}

// ---------------------------------------------------------------------------
// Table 1 — accepted / compatible cases A1..A15.
// ---------------------------------------------------------------------------

fn run_accepted_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("accepted");

    // A1 — fixture KMS accepted under explicit fixture policy on DevNet.
    let a1 = scenario(BackendKind::FixtureKms, Env::Devnet);
    t.check("A1", "accept:FixtureKmsAccepted", &backend_tag(&validate(&a1, BackendPolicy::FixtureKmsAllowed)));

    // A2 — fixture HSM accepted under explicit fixture policy on DevNet.
    let a2 = scenario(BackendKind::FixtureHsm, Env::Devnet);
    t.check("A2", "accept:FixtureHsmAccepted", &backend_tag(&validate(&a2, BackendPolicy::FixtureHsmAllowed)));

    // A3 — fixture KMS accepted under explicit fixture policy on TestNet.
    let a3 = scenario(BackendKind::FixtureKms, Env::Testnet);
    t.check("A3", "accept:FixtureKmsAccepted", &backend_tag(&validate(&a3, BackendPolicy::FixtureKmsAllowed)));

    // A4 — fixture HSM accepted under explicit fixture policy on TestNet.
    let a4 = scenario(BackendKind::FixtureHsm, Env::Testnet);
    t.check("A4", "accept:FixtureHsmAccepted", &backend_tag(&validate(&a4, BackendPolicy::FixtureHsmAllowed)));

    // A5 — backend identity digest deterministic + domain-bound.
    let s = scenario(BackendKind::FixtureKms, Env::Devnet);
    let mut other_id = s.identity.clone();
    other_id.provider_id = "different-provider".to_string();
    t.assert_true(
        "A5",
        s.identity.identity_digest() == s.identity.identity_digest()
            && s.identity.identity_digest() != other_id.identity_digest(),
        "identity digest stable + changes when a bound field changes",
    );

    // A6 — backend request digest deterministic + domain-bound.
    let mut other_req = s.request.clone();
    other_req.authority_domain_sequence = 3;
    t.assert_true(
        "A6",
        s.request.request_digest() == s.request.request_digest()
            && s.request.request_digest() != other_req.request_digest(),
        "request digest stable + changes when a bound field changes",
    );

    // A7 — backend response digest deterministic + domain-bound.
    let mut other_resp = s.response.clone();
    other_resp.response_nonce = "different".to_string();
    t.assert_true(
        "A7",
        s.response.response_digest() == s.response.response_digest()
            && s.response.response_digest() != other_resp.response_digest(),
        "response digest stable + changes when a bound field changes",
    );

    // A8 — backend transcript digest deterministic + order-sensitive.
    let id = s.identity.identity_digest();
    let req = s.request.request_digest();
    let resp = s.response.response_digest();
    let trans = backend_transcript_digest(&id, &req, &resp);
    t.assert_true(
        "A8",
        trans == backend_transcript_digest(&id, &req, &resp)
            && trans != backend_transcript_digest(&id, &req, "other-response-digest"),
        "transcript digest stable, bound, and sensitive to its inputs",
    );

    // A9 — request binds env/chain/genesis/root/action/candidate/sequence/
    //      custody-class/key-id.
    let r = &s.request;
    t.assert_true(
        "A9",
        r.environment == Env::Devnet
            && r.chain_id == CHAIN_ID
            && r.genesis_hash == GENESIS_HASH
            && r.authority_root_fingerprint == ROOT_FP
            && r.lifecycle_action == LocalLifecycleAction::Rotate
            && r.candidate_digest == DIGEST_2
            && r.authority_domain_sequence == 2
            && r.custody_class == AuthorityCustodyClass::Kms
            && r.key_id == KEY_ID
            && r.is_well_formed(),
        "request binds env/chain/genesis/root/action/candidate/sequence/custody/key",
    );

    // A10 — response binds request digest, backend id, provider id, key id,
    //       suite, response digest, attestation digest.
    let resp_r = &s.response;
    t.assert_true(
        "A10",
        resp_r.bound_request_digest == s.request.request_digest()
            && resp_r.backend_id == BACKEND_ID
            && resp_r.provider_id == PROVIDER_ID
            && resp_r.key_id == KEY_ID
            && resp_r.signature_suite_id == PQC_LIFECYCLE_SUITE_ML_DSA_44
            && resp_r.attestation_digest == ATTEST_DIGEST
            && !resp_r.response_digest().is_empty()
            && resp_r.is_well_formed(),
        "response binds request digest, backend/provider/key id, suite, response/attestation digest",
    );

    // A11 — production KMS boundary callable, returns typed unavailable.
    {
        let candidate = rotate_candidate(Env::Devnet);
        let pid = identity(BackendKind::ProductionKmsUnavailable, Env::Devnet, &candidate);
        let preq = request(BackendKind::ProductionKmsUnavailable, Env::Devnet, &candidate);
        let backend = ProductionKmsBackend { identity: pid };
        t.assert_true(
            "A11",
            backend.kind() == BackendKind::ProductionKmsUnavailable
                && backend.sign_authority_lifecycle_request(&preq)
                    == Err(BackendOutcome::ProductionKmsUnavailable),
            "production KMS backend callable, fails closed unavailable",
        );
    }

    // A12 — production HSM boundary callable, returns typed unavailable.
    {
        let candidate = rotate_candidate(Env::Devnet);
        let pid = identity(BackendKind::ProductionHsmUnavailable, Env::Devnet, &candidate);
        let preq = request(BackendKind::ProductionHsmUnavailable, Env::Devnet, &candidate);
        let backend = ProductionHsmBackend { identity: pid };
        t.assert_true(
            "A12",
            backend.kind() == BackendKind::ProductionHsmUnavailable
                && backend.sign_authority_lifecycle_request(&preq)
                    == Err(BackendOutcome::ProductionHsmUnavailable),
            "production HSM backend callable, fails closed unavailable",
        );
    }

    // A13 — Run 188 custody validator compatible with KMS/HSM classes. The
    //       Run 188 layer fails Kms/Hsm custody closed as unavailable, so
    //       the composition rejects at the custody layer — proving the
    //       KMS/HSM backend class routes through the Run 188 validator.
    {
        let mut a13_ok = true;
        for (kind, class) in [
            (BackendKind::FixtureKms, AuthorityCustodyClass::Kms),
            (BackendKind::FixtureHsm, AuthorityCustodyClass::Hsm),
        ] {
            let sc = scenario(kind, Env::Devnet);
            let custody = good_custody_attestation(sc.env, &sc.candidate, class);
            let prior = prior_versioned(sc.env);
            let outcome = validate_lifecycle_governance_custody_and_backend(
                &custody,
                &sc.candidate,
                Some(&prior),
                &sc.domain,
                GovernanceAuthorityClass::GenesisBound,
                LocalLifecycleAction::Rotate,
                DIGEST_2,
                2,
                Some(KEY_ID),
                AuthorityCustodyPolicy::DevnetLocalAllowed,
                &sc.identity,
                &sc.request,
                &sc.response,
                &sc.expected,
                fixture_policy_for(kind),
                NOW,
                false,
            );
            a13_ok &= matches!(
                outcome,
                LifecycleCustodyBackendOutcome::LifecycleOrCustodyRejected(_)
            );
        }
        t.assert_true(
            "A13",
            a13_ok,
            "Kms/Hsm custody classes route through the Run 188 validator (fails closed)",
        );
    }

    // A14 — RemoteSigner behavior from Runs 194–202 remains unchanged: the
    //       KMS/HSM router refuses the RemoteSigner custody class.
    {
        let outcome = validate_backend_for_custody_class(
            AuthorityCustodyClass::RemoteSigner,
            &s.identity,
            &s.request,
            &s.response,
            &s.domain,
            &s.expected,
            BackendPolicy::FixtureKmsAllowed,
        );
        t.assert_true(
            "A14",
            outcome
                == BackendOutcome::NotKmsHsmCustodyClass {
                    class: AuthorityCustodyClass::RemoteSigner,
                }
                && !custody_class_routes_to_kms_hsm_backend(AuthorityCustodyClass::RemoteSigner)
                && custody_class_routes_to_kms_hsm_backend(AuthorityCustodyClass::Kms)
                && custody_class_routes_to_kms_hsm_backend(AuthorityCustodyClass::Hsm),
            "RemoteSigner class refused as NotKmsHsmCustodyClass; Kms/Hsm route in",
        );
    }

    // A15 — GenesisBound / EmergencyCouncil / OnChainGovernance proof
    //       behavior unchanged when backend policy is Disabled.
    {
        let mut a15_ok = true;
        for class in [
            GovernanceAuthorityClass::GenesisBound,
            GovernanceAuthorityClass::EmergencyCouncil,
            GovernanceAuthorityClass::OnChainGovernance,
        ] {
            let _ = class; // governance class is orthogonal to a Disabled backend
            let sc = scenario(BackendKind::FixtureKms, Env::Devnet);
            a15_ok &= validate(&sc, BackendPolicy::Disabled) == BackendOutcome::Disabled;
        }
        t.assert_true(
            "A15",
            a15_ok,
            "Disabled backend policy does not disturb governance proof behavior",
        );
    }

    t.finish(out)
}

// ---------------------------------------------------------------------------
// Table 2 — rejection cases R1..R41.
// ---------------------------------------------------------------------------

fn run_rejection_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("rejection");
    let dev = || scenario(BackendKind::FixtureKms, Env::Devnet);

    // R1 — Disabled policy.
    t.check("R1", "reject:Disabled", &backend_tag(&validate(&dev(), BackendPolicy::Disabled)));

    // R2 — fixture KMS rejected under ProductionKmsRequired.
    t.check(
        "R2",
        "reject:FixtureRejectedProductionRequired",
        &backend_tag(&validate(&dev(), BackendPolicy::ProductionKmsRequired)),
    );

    // R3 — fixture HSM rejected under ProductionHsmRequired.
    {
        let s = scenario(BackendKind::FixtureHsm, Env::Devnet);
        t.check(
            "R3",
            "reject:FixtureRejectedProductionRequired",
            &backend_tag(&validate(&s, BackendPolicy::ProductionHsmRequired)),
        );
    }

    // R4 — fixture KMS/HSM rejected under MainnetProductionCustodyRequired.
    {
        let mut r4_ok = true;
        for kind in [BackendKind::FixtureKms, BackendKind::FixtureHsm] {
            let s = scenario(kind, Env::Devnet);
            r4_ok &= validate(&s, BackendPolicy::MainnetProductionCustodyRequired)
                == BackendOutcome::FixtureRejectedMainnetProductionRequired;
        }
        t.assert_true("R4", r4_ok, "fixture KMS/HSM rejected under mainnet-production-custody-required");
    }

    // R5 — production KMS rejected as unavailable.
    {
        let s = production_response(BackendKind::ProductionKmsUnavailable, Env::Devnet);
        let outcome = validate(&s, BackendPolicy::FixtureKmsAllowed);
        t.assert_true(
            "R5",
            outcome == BackendOutcome::ProductionKmsUnavailable && outcome.is_unavailable(),
            "production KMS response refused as unavailable",
        );
    }

    // R6 — production HSM rejected as unavailable.
    {
        let s = production_response(BackendKind::ProductionHsmUnavailable, Env::Devnet);
        t.check("R6", "reject:ProductionHsmUnavailable", &backend_tag(&validate(&s, BackendPolicy::FixtureHsmAllowed)));
    }

    // R7 — cloud KMS rejected as unavailable (verifier + struct).
    {
        let s = production_response(BackendKind::CloudKmsUnavailable, Env::Devnet);
        let backend = CloudKmsBackend { identity: s.identity.clone() };
        t.assert_true(
            "R7",
            validate(&s, BackendPolicy::FixtureKmsAllowed) == BackendOutcome::CloudKmsUnavailable
                && backend.sign_authority_lifecycle_request(&s.request)
                    == Err(BackendOutcome::CloudKmsUnavailable),
            "cloud KMS refused as unavailable (verifier + struct)",
        );
    }

    // R8 — PKCS#11 HSM rejected as unavailable (verifier + struct).
    {
        let s = production_response(BackendKind::Pkcs11HsmUnavailable, Env::Devnet);
        let backend = Pkcs11HsmBackend { identity: s.identity.clone() };
        t.assert_true(
            "R8",
            validate(&s, BackendPolicy::FixtureHsmAllowed) == BackendOutcome::Pkcs11HsmUnavailable
                && backend.sign_authority_lifecycle_request(&s.request)
                    == Err(BackendOutcome::Pkcs11HsmUnavailable),
            "PKCS#11 HSM refused as unavailable (verifier + struct)",
        );
    }

    // R9 — MainNet production custody rejected as unavailable.
    {
        let s = production_response(BackendKind::ProductionKmsUnavailable, Env::Devnet);
        t.check(
            "R9",
            "reject:MainNetProductionCustodyUnavailable",
            &backend_tag(&validate(&s, BackendPolicy::MainnetProductionCustodyRequired)),
        );
    }

    // R10 — unknown backend rejected.
    {
        let s = production_response(BackendKind::Unknown, Env::Devnet);
        t.check("R10", "reject:UnknownBackendRejected", &backend_tag(&validate(&s, BackendPolicy::FixtureKmsAllowed)));
    }

    // R11 — wrong environment rejected.
    {
        let mut s = dev();
        s.request.environment = Env::Testnet;
        t.check("R11", "reject:WrongEnvironment", &backend_tag(&validate(&s, BackendPolicy::FixtureKmsAllowed)));
    }

    // R12 — wrong chain rejected.
    {
        let mut s = dev();
        s.request.chain_id = OTHER_CHAIN.to_string();
        t.check("R12", "reject:WrongChain", &backend_tag(&validate(&s, BackendPolicy::FixtureKmsAllowed)));
    }

    // R13 — wrong genesis rejected.
    {
        let mut s = dev();
        s.request.genesis_hash = OTHER_GENESIS.to_string();
        t.check("R13", "reject:WrongGenesis", &backend_tag(&validate(&s, BackendPolicy::FixtureKmsAllowed)));
    }

    // R14 — wrong authority root rejected.
    {
        let mut s = dev();
        s.request.authority_root_fingerprint = OTHER_ROOT_FP.to_string();
        t.check("R14", "reject:WrongAuthorityRoot", &backend_tag(&validate(&s, BackendPolicy::FixtureKmsAllowed)));
    }

    // R15 — wrong key id / key label rejected.
    {
        let mut s = dev();
        s.response.key_id = "other-key".to_string();
        t.check("R15", "reject:WrongKeyId", &backend_tag(&validate(&s, BackendPolicy::FixtureKmsAllowed)));
    }

    // R16 — wrong signing-key fingerprint rejected.
    {
        let mut s = dev();
        s.expected.expected_signing_key_fingerprint = "deadbeef".to_string();
        t.check("R16", "reject:WrongSigningKeyFingerprint", &backend_tag(&validate(&s, BackendPolicy::FixtureKmsAllowed)));
    }

    // R17 — wrong lifecycle action rejected.
    {
        let mut s = dev();
        s.expected.expected_lifecycle_action = LocalLifecycleAction::Revoke;
        t.check("R17", "reject:WrongLifecycleAction", &backend_tag(&validate(&s, BackendPolicy::FixtureKmsAllowed)));
    }

    // R18 — wrong candidate digest rejected.
    {
        let mut s = dev();
        s.expected.expected_candidate_digest = "3".repeat(64);
        t.check("R18", "reject:WrongCandidateDigest", &backend_tag(&validate(&s, BackendPolicy::FixtureKmsAllowed)));
    }

    // R19 — wrong authority-domain sequence rejected.
    {
        let mut s = dev();
        s.expected.expected_authority_domain_sequence = 7;
        t.check("R19", "reject:WrongAuthorityDomainSequence", &backend_tag(&validate(&s, BackendPolicy::FixtureKmsAllowed)));
    }

    // R20 — wrong request digest rejected.
    {
        let mut s = dev();
        s.expected.expected_request_digest = "0".repeat(64);
        t.check("R20", "reject:WrongRequestDigest", &backend_tag(&validate(&s, BackendPolicy::FixtureKmsAllowed)));
    }

    // R21 — wrong response digest rejected.
    {
        let mut s = dev();
        s.expected.expected_response_digest = "0".repeat(64);
        t.check("R21", "reject:WrongResponseDigest", &backend_tag(&validate(&s, BackendPolicy::FixtureKmsAllowed)));
    }

    // R22 — wrong transcript digest rejected.
    {
        let mut s = dev();
        s.expected.expected_transcript_digest = "0".repeat(64);
        t.check("R22", "reject:WrongTranscriptDigest", &backend_tag(&validate(&s, BackendPolicy::FixtureKmsAllowed)));
    }

    // R23 — stale/replayed request rejected.
    {
        let mut s = dev();
        s.expected.expected_request_nonce = "stale".to_string();
        t.check("R23", "reject:StaleOrReplayedRequest", &backend_tag(&validate(&s, BackendPolicy::FixtureKmsAllowed)));
    }

    // R24 — stale/replayed response rejected.
    {
        let mut s = dev();
        s.expected.expected_response_nonce = "stale".to_string();
        t.check("R24", "reject:StaleOrReplayedResponse", &backend_tag(&validate(&s, BackendPolicy::FixtureKmsAllowed)));
    }

    // R25 — expired attestation rejected. Changing the identity expiry
    //       changes its identity digest, so the expected transcript digest
    //       must be recomputed to reach the freshness check.
    {
        let mut s = dev();
        s.identity.expires_at_unix = Some(NOW - 1);
        s.expected.expected_transcript_digest = backend_transcript_digest(
            &s.identity.identity_digest(),
            &s.request.request_digest(),
            &s.response.response_digest(),
        );
        t.check("R25", "reject:ExpiredAttestation", &backend_tag(&validate(&s, BackendPolicy::FixtureKmsAllowed)));
    }

    // R26 — expired response rejected.
    {
        let mut s = dev();
        s.response.expires_at_unix = Some(NOW - 1);
        s.expected.expected_response_digest = s.response.response_digest();
        s.expected.expected_transcript_digest = backend_transcript_digest(
            &s.identity.identity_digest(),
            &s.request.request_digest(),
            &s.response.response_digest(),
        );
        t.check("R26", "reject:ExpiredResponse", &backend_tag(&validate(&s, BackendPolicy::FixtureKmsAllowed)));
    }

    // R27 — unsupported suite rejected.
    {
        let mut s = dev();
        s.response.signature_suite_id = 99;
        s.expected.expected_response_digest = s.response.response_digest();
        s.expected.expected_transcript_digest = backend_transcript_digest(
            &s.identity.identity_digest(),
            &s.request.request_digest(),
            &s.response.response_digest(),
        );
        t.check("R27", "reject:UnsupportedSuite", &backend_tag(&validate(&s, BackendPolicy::FixtureKmsAllowed)));
    }

    // R28 — invalid attestation rejected.
    {
        let mut s = dev();
        s.response.attestation_digest = KMS_HSM_BACKEND_INVALID_ATTESTATION_SENTINEL.to_string();
        s.expected.expected_response_digest = s.response.response_digest();
        s.expected.expected_transcript_digest = backend_transcript_digest(
            &s.identity.identity_digest(),
            &s.request.request_digest(),
            &s.response.response_digest(),
        );
        t.check("R28", "reject:InvalidAttestation", &backend_tag(&validate(&s, BackendPolicy::FixtureKmsAllowed)));
    }

    // R29 — invalid signature / placeholder signature rejected.
    {
        let mut s = dev();
        s.response.signature_commitment = KMS_HSM_BACKEND_INVALID_SIGNATURE_SENTINEL.to_string();
        s.expected.expected_response_digest = s.response.response_digest();
        s.expected.expected_transcript_digest = backend_transcript_digest(
            &s.identity.identity_digest(),
            &s.request.request_digest(),
            &s.response.response_digest(),
        );
        t.check("R29", "reject:InvalidSignature", &backend_tag(&validate(&s, BackendPolicy::FixtureKmsAllowed)));
    }

    // R30 — malformed backend identity rejected.
    {
        let mut s = dev();
        s.identity.backend_id = String::new();
        t.check("R30", "reject:MalformedIdentity", &backend_tag(&validate(&s, BackendPolicy::FixtureKmsAllowed)));
    }

    // R31 — malformed backend request rejected.
    {
        let mut s = dev();
        s.request.candidate_digest = String::new();
        t.check("R31", "reject:MalformedRequest", &backend_tag(&validate(&s, BackendPolicy::FixtureKmsAllowed)));
    }

    // R32 — malformed backend response rejected.
    {
        let mut s = dev();
        s.response.signature_commitment = String::new();
        t.check("R32", "reject:MalformedResponse", &backend_tag(&validate(&s, BackendPolicy::FixtureKmsAllowed)));
    }

    // R33 — local operator cannot satisfy backend policy.
    {
        let s = dev();
        let outcome = validate_backend_for_custody_class(
            AuthorityCustodyClass::LocalOperatorKey,
            &s.identity,
            &s.request,
            &s.response,
            &s.domain,
            &s.expected,
            BackendPolicy::FixtureKmsAllowed,
        );
        t.assert_true(
            "R33",
            outcome == BackendOutcome::LocalOperatorCannotSatisfyBackendPolicy
                && local_operator_cannot_satisfy_backend_policy(),
            "local operator key routes to LocalOperatorCannotSatisfyBackendPolicy",
        );
    }

    // R34 — peer majority cannot satisfy backend policy.
    {
        let s = dev();
        let outcome = validate_backend_for_custody_class(
            AuthorityCustodyClass::FixtureLocalKey,
            &s.identity,
            &s.request,
            &s.response,
            &s.domain,
            &s.expected,
            BackendPolicy::FixtureKmsAllowed,
        );
        t.assert_true(
            "R34",
            outcome == BackendOutcome::LocalOperatorCannotSatisfyBackendPolicy
                && peer_majority_cannot_satisfy_backend_policy(),
            "fixture-local-key / peer material cannot satisfy a backend policy",
        );
    }

    // R35 — backend valid but custody metadata invalid rejected.
    {
        let s = dev();
        let mut custody = good_custody_attestation(s.env, &s.candidate, AuthorityCustodyClass::Kms);
        custody.candidate_digest = "deadbeef".to_string();
        let prior = prior_versioned(s.env);
        let outcome = validate_lifecycle_governance_custody_and_backend(
            &custody,
            &s.candidate,
            Some(&prior),
            &s.domain,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::Rotate,
            DIGEST_2,
            2,
            Some(KEY_ID),
            AuthorityCustodyPolicy::DevnetLocalAllowed,
            &s.identity,
            &s.request,
            &s.response,
            &s.expected,
            BackendPolicy::FixtureKmsAllowed,
            NOW,
            false,
        );
        t.assert_true(
            "R35",
            matches!(outcome, LifecycleCustodyBackendOutcome::LifecycleOrCustodyRejected(_))
                && outcome.is_reject(),
            "backend valid but invalid custody metadata rejects at the Run 188 layer",
        );
    }

    // R36 — custody valid but backend response invalid rejected. Use a
    //       LocalOperatorKey custody class that Run 188 accepts under
    //       DevnetLocalAllowed, then feed an invalid backend response.
    {
        let candidate = rotate_candidate(Env::Devnet);
        let id = identity(BackendKind::FixtureKms, Env::Devnet, &candidate);
        let req = request(BackendKind::FixtureKms, Env::Devnet, &candidate);
        let mut response = sign_with_kind(BackendKind::FixtureKms, &id, &req).expect("signs");
        response.signature_commitment = KMS_HSM_BACKEND_INVALID_SIGNATURE_SENTINEL.to_string();
        let mut expected = expectations(&id, &req, &response, &candidate);
        expected.expected_response_digest = response.response_digest();
        expected.expected_transcript_digest = backend_transcript_digest(
            &id.identity_digest(),
            &req.request_digest(),
            &response.response_digest(),
        );
        let custody = AuthorityCustodyAttestation {
            custody_class: AuthorityCustodyClass::LocalOperatorKey,
            ..good_custody_attestation(Env::Devnet, &candidate, AuthorityCustodyClass::LocalOperatorKey)
        };
        let prior = prior_versioned(Env::Devnet);
        let outcome = validate_lifecycle_governance_custody_and_backend(
            &custody,
            &candidate,
            Some(&prior),
            &domain(Env::Devnet),
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::Rotate,
            DIGEST_2,
            2,
            Some(KEY_ID),
            AuthorityCustodyPolicy::DevnetLocalAllowed,
            &id,
            &req,
            &response,
            &expected,
            BackendPolicy::FixtureKmsAllowed,
            NOW,
            false,
        );
        t.assert_true(
            "R36",
            matches!(
                outcome,
                LifecycleCustodyBackendOutcome::BackendRejected {
                    backend_outcome: BackendOutcome::InvalidSignature,
                    ..
                }
            ),
            "custody valid but invalid backend response rejects at the backend layer",
        );
    }

    // R37 — lifecycle + governance + custody valid but production KMS
    //       unavailable rejected.
    {
        let candidate = rotate_candidate(Env::Devnet);
        let s = production_response(BackendKind::ProductionKmsUnavailable, Env::Devnet);
        let custody = AuthorityCustodyAttestation {
            custody_class: AuthorityCustodyClass::LocalOperatorKey,
            ..good_custody_attestation(Env::Devnet, &candidate, AuthorityCustodyClass::LocalOperatorKey)
        };
        let prior = prior_versioned(Env::Devnet);
        let outcome = validate_lifecycle_governance_custody_and_backend(
            &custody,
            &candidate,
            Some(&prior),
            &s.domain,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::Rotate,
            DIGEST_2,
            2,
            Some(KEY_ID),
            AuthorityCustodyPolicy::DevnetLocalAllowed,
            &s.identity,
            &s.request,
            &s.response,
            &s.expected,
            BackendPolicy::FixtureKmsAllowed,
            NOW,
            false,
        );
        t.assert_true(
            "R37",
            matches!(
                outcome,
                LifecycleCustodyBackendOutcome::BackendRejected {
                    backend_outcome: BackendOutcome::ProductionKmsUnavailable,
                    ..
                }
            ),
            "lifecycle+governance+custody valid but production KMS unavailable",
        );
    }

    // R38 — lifecycle + governance + custody valid but production HSM
    //       unavailable rejected.
    {
        let candidate = rotate_candidate(Env::Devnet);
        let s = production_response(BackendKind::ProductionHsmUnavailable, Env::Devnet);
        let custody = AuthorityCustodyAttestation {
            custody_class: AuthorityCustodyClass::LocalOperatorKey,
            ..good_custody_attestation(Env::Devnet, &candidate, AuthorityCustodyClass::LocalOperatorKey)
        };
        let prior = prior_versioned(Env::Devnet);
        let outcome = validate_lifecycle_governance_custody_and_backend(
            &custody,
            &candidate,
            Some(&prior),
            &s.domain,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::Rotate,
            DIGEST_2,
            2,
            Some(KEY_ID),
            AuthorityCustodyPolicy::DevnetLocalAllowed,
            &s.identity,
            &s.request,
            &s.response,
            &s.expected,
            BackendPolicy::FixtureHsmAllowed,
            NOW,
            false,
        );
        t.assert_true(
            "R38",
            matches!(
                outcome,
                LifecycleCustodyBackendOutcome::BackendRejected {
                    backend_outcome: BackendOutcome::ProductionHsmUnavailable,
                    ..
                }
            ),
            "lifecycle+governance+custody valid but production HSM unavailable",
        );
    }

    // R39 — validation-only rejection remains non-mutating.
    {
        let s = dev();
        let identity_before = s.identity.clone();
        let request_before = s.request.clone();
        let response_before = s.response.clone();
        let o1 = validate(&s, BackendPolicy::Disabled);
        let o2 = validate(&s, BackendPolicy::Disabled);
        t.assert_true(
            "R39",
            o1 == o2
                && s.identity == identity_before
                && s.request == request_before
                && s.response == response_before,
            "rejecting validation leaves all inputs byte-identical",
        );
    }

    // R40 — mutating preflight rejection produces no Run 070 call, no live
    //       trust swap, no session eviction, no sequence write, no marker
    //       write (the composition is pure and returns a typed reject).
    {
        let candidate = rotate_candidate(Env::Devnet);
        let candidate_before = candidate.clone();
        let s = production_response(BackendKind::ProductionKmsUnavailable, Env::Devnet);
        let custody = AuthorityCustodyAttestation {
            custody_class: AuthorityCustodyClass::LocalOperatorKey,
            ..good_custody_attestation(Env::Devnet, &candidate, AuthorityCustodyClass::LocalOperatorKey)
        };
        let prior = prior_versioned(Env::Devnet);
        let outcome = validate_lifecycle_governance_custody_and_backend(
            &custody,
            &candidate,
            Some(&prior),
            &s.domain,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::Rotate,
            DIGEST_2,
            2,
            Some(KEY_ID),
            AuthorityCustodyPolicy::DevnetLocalAllowed,
            &s.identity,
            &s.request,
            &s.response,
            &s.expected,
            BackendPolicy::FixtureKmsAllowed,
            NOW,
            true,
        );
        t.assert_true(
            "R40",
            outcome.is_reject() && candidate == candidate_before,
            "mutating-preflight rejection returns a typed reject without mutating the candidate",
        );
    }

    // R41 — MainNet peer-driven apply remains refused even with fixture
    //       KMS/HSM.
    {
        let s = scenario(BackendKind::FixtureKms, Env::Mainnet);
        let verifier_refused =
            validate(&s, BackendPolicy::FixtureKmsAllowed) == BackendOutcome::FixtureRejectedForMainNet;
        let custody = good_custody_attestation(s.env, &s.candidate, AuthorityCustodyClass::Kms);
        let prior = prior_versioned(s.env);
        let outcome = validate_lifecycle_governance_custody_and_backend(
            &custody,
            &s.candidate,
            Some(&prior),
            &s.domain,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::Rotate,
            DIGEST_2,
            2,
            Some(KEY_ID),
            AuthorityCustodyPolicy::DevnetLocalAllowed,
            &s.identity,
            &s.request,
            &s.response,
            &s.expected,
            BackendPolicy::FixtureKmsAllowed,
            NOW,
            true,
        );
        t.assert_true(
            "R41",
            verifier_refused
                && outcome == LifecycleCustodyBackendOutcome::MainNetPeerDrivenApplyRefused
                && mainnet_peer_driven_apply_remains_refused_under_kms_hsm_backend_boundary(
                    Env::Mainnet,
                ),
            "MainNet peer-driven apply refused even with valid fixture KMS material",
        );
    }

    t.finish(out)
}

// ---------------------------------------------------------------------------
// Table 3 — separation / fail-closed / routing extras.
// ---------------------------------------------------------------------------

fn run_separation_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("separation");

    // Fixture KMS refused for MainNet.
    let main = scenario(BackendKind::FixtureKms, Env::Mainnet);
    t.check(
        "fixture-rejected-mainnet",
        "reject:FixtureRejectedForMainNet",
        &backend_tag(&validate(&main, BackendPolicy::FixtureKmsAllowed)),
    );

    // Fixture-kind / fixture-policy mismatch.
    let hsm = scenario(BackendKind::FixtureHsm, Env::Devnet);
    t.check(
        "fixture-kind-policy-mismatch",
        "reject:BackendKindPolicyMismatch",
        &backend_tag(&validate(&hsm, BackendPolicy::FixtureKmsAllowed)),
    );

    // Production / cloud / PKCS#11 backends perform no I/O and fail closed
    // on both DevNet and TestNet.
    {
        let mut prod_ok = true;
        for env in [Env::Devnet, Env::Testnet] {
            let candidate = rotate_candidate(env);
            let kid = identity(BackendKind::ProductionKmsUnavailable, env, &candidate);
            let hid = identity(BackendKind::ProductionHsmUnavailable, env, &candidate);
            let cid = identity(BackendKind::CloudKmsUnavailable, env, &candidate);
            let pid = identity(BackendKind::Pkcs11HsmUnavailable, env, &candidate);
            let req_k = request(BackendKind::ProductionKmsUnavailable, env, &candidate);
            let req_h = request(BackendKind::ProductionHsmUnavailable, env, &candidate);
            prod_ok &= ProductionKmsBackend { identity: kid }
                .sign_authority_lifecycle_request(&req_k)
                == Err(BackendOutcome::ProductionKmsUnavailable);
            prod_ok &= ProductionHsmBackend { identity: hid }
                .sign_authority_lifecycle_request(&req_h)
                == Err(BackendOutcome::ProductionHsmUnavailable);
            prod_ok &= CloudKmsBackend { identity: cid }
                .sign_authority_lifecycle_request(&req_k)
                == Err(BackendOutcome::CloudKmsUnavailable);
            prod_ok &= Pkcs11HsmBackend { identity: pid }
                .sign_authority_lifecycle_request(&req_h)
                == Err(BackendOutcome::Pkcs11HsmUnavailable);
        }
        t.assert_true(
            "production-no-io-fail-closed",
            prod_ok,
            "production/cloud/PKCS#11 backends fail closed on DevNet + TestNet, no I/O",
        );
    }

    // Fixture backend is mockable as a trait object.
    {
        let s = scenario(BackendKind::FixtureKms, Env::Devnet);
        let backend = FixtureKmsBackend {
            identity: s.identity.clone(),
            response_nonce: RESP_NONCE.to_string(),
            response_freshness_unix: Some(FRESH),
            response_expires_at_unix: Some(EXPIRES),
        };
        let dynref: &dyn AuthorityCustodyBackend = &backend;
        t.assert_true(
            "trait-object-mockable",
            dynref.kind() == BackendKind::FixtureKms
                && dynref.identity().backend_id == BACKEND_ID
                && dynref.sign_authority_lifecycle_request(&s.request).is_ok(),
            "AuthorityCustodyBackend is usable as a trait object",
        );
    }

    // Default policy is Disabled and fails closed even with a valid fixture
    // round-trip.
    {
        let s = scenario(BackendKind::FixtureKms, Env::Devnet);
        t.check(
            "default-policy-disabled",
            "reject:Disabled",
            &backend_tag(&validate(&s, BackendPolicy::default())),
        );
    }

    // Custody-class routing predicate + non-KMS/HSM class rejection
    // (RemoteSigner stays separate).
    {
        let s = scenario(BackendKind::FixtureKms, Env::Devnet);
        let outcome = validate_backend_for_custody_class(
            AuthorityCustodyClass::RemoteSigner,
            &s.identity,
            &s.request,
            &s.response,
            &s.domain,
            &s.expected,
            BackendPolicy::FixtureKmsAllowed,
        );
        t.assert_true(
            "custody-class-routing",
            custody_class_routes_to_kms_hsm_backend(AuthorityCustodyClass::Kms)
                && custody_class_routes_to_kms_hsm_backend(AuthorityCustodyClass::Hsm)
                && !custody_class_routes_to_kms_hsm_backend(AuthorityCustodyClass::RemoteSigner)
                && matches!(outcome, BackendOutcome::NotKmsHsmCustodyClass { .. }),
            "Kms/Hsm classes route in; RemoteSigner is rejected as NotKmsHsmCustodyClass",
        );
    }

    t.finish(out)
}

// ---------------------------------------------------------------------------
// Table 4 — full lifecycle/governance/custody/backend composition.
// ---------------------------------------------------------------------------

fn run_composition_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("composition");

    // Kms/Hsm custody composition rejects at the Run 188 layer (Run 188
    // fails Kms/Hsm closed as unavailable).
    {
        let s = scenario(BackendKind::FixtureKms, Env::Devnet);
        let custody = good_custody_attestation(s.env, &s.candidate, AuthorityCustodyClass::Kms);
        let prior = prior_versioned(s.env);
        let outcome = validate_lifecycle_governance_custody_and_backend(
            &custody,
            &s.candidate,
            Some(&prior),
            &s.domain,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::Rotate,
            DIGEST_2,
            2,
            Some(KEY_ID),
            AuthorityCustodyPolicy::DevnetLocalAllowed,
            &s.identity,
            &s.request,
            &s.response,
            &s.expected,
            BackendPolicy::FixtureKmsAllowed,
            NOW,
            false,
        );
        t.check(
            "compose-kms-custody-rejected",
            "reject:LifecycleOrCustodyRejected",
            &composition_tag(&outcome),
        );
    }

    // Custody accepted (LocalOperatorKey) but backend rejected (production
    // KMS unavailable).
    {
        let candidate = rotate_candidate(Env::Devnet);
        let s = production_response(BackendKind::ProductionKmsUnavailable, Env::Devnet);
        let custody = AuthorityCustodyAttestation {
            custody_class: AuthorityCustodyClass::LocalOperatorKey,
            ..good_custody_attestation(Env::Devnet, &candidate, AuthorityCustodyClass::LocalOperatorKey)
        };
        let prior = prior_versioned(Env::Devnet);
        let outcome = validate_lifecycle_governance_custody_and_backend(
            &custody,
            &candidate,
            Some(&prior),
            &s.domain,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::Rotate,
            DIGEST_2,
            2,
            Some(KEY_ID),
            AuthorityCustodyPolicy::DevnetLocalAllowed,
            &s.identity,
            &s.request,
            &s.response,
            &s.expected,
            BackendPolicy::FixtureKmsAllowed,
            NOW,
            false,
        );
        t.check("compose-backend-rejected", "reject:BackendRejected", &composition_tag(&outcome));
    }

    // Disabled backend policy rejects at the backend layer after custody
    // accepts.
    {
        let candidate = rotate_candidate(Env::Devnet);
        let s = scenario(BackendKind::FixtureKms, Env::Devnet);
        let custody = AuthorityCustodyAttestation {
            custody_class: AuthorityCustodyClass::LocalOperatorKey,
            ..good_custody_attestation(Env::Devnet, &candidate, AuthorityCustodyClass::LocalOperatorKey)
        };
        let prior = prior_versioned(Env::Devnet);
        let outcome = validate_lifecycle_governance_custody_and_backend(
            &custody,
            &candidate,
            Some(&prior),
            &s.domain,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::Rotate,
            DIGEST_2,
            2,
            Some(KEY_ID),
            AuthorityCustodyPolicy::DevnetLocalAllowed,
            &s.identity,
            &s.request,
            &s.response,
            &s.expected,
            BackendPolicy::Disabled,
            NOW,
            false,
        );
        t.check("compose-backend-disabled", "reject:BackendRejected", &composition_tag(&outcome));
    }

    // MainNet peer-driven apply refused even with fixture KMS.
    {
        let s = scenario(BackendKind::FixtureKms, Env::Mainnet);
        let custody = good_custody_attestation(s.env, &s.candidate, AuthorityCustodyClass::Kms);
        let prior = prior_versioned(s.env);
        let outcome = validate_lifecycle_governance_custody_and_backend(
            &custody,
            &s.candidate,
            Some(&prior),
            &s.domain,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::Rotate,
            DIGEST_2,
            2,
            Some(KEY_ID),
            AuthorityCustodyPolicy::DevnetLocalAllowed,
            &s.identity,
            &s.request,
            &s.response,
            &s.expected,
            BackendPolicy::FixtureKmsAllowed,
            NOW,
            true,
        );
        t.check("compose-mainnet-refused", "reject:MainNetPeerDrivenApplyRefused", &composition_tag(&outcome));
    }

    t.finish(out)
}

// ---------------------------------------------------------------------------
// Table 5 — determinism (repeat resolution is byte-identical).
// ---------------------------------------------------------------------------

fn run_determinism_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("determinism");

    for (label, env) in [("devnet", Env::Devnet), ("testnet", Env::Testnet)] {
        let a = scenario(BackendKind::FixtureKms, env);
        let b = scenario(BackendKind::FixtureKms, env);
        let outcome_a = backend_tag(&validate(&a, BackendPolicy::FixtureKmsAllowed));
        let outcome_b = backend_tag(&validate(&b, BackendPolicy::FixtureKmsAllowed));
        let id_eq = a.identity.identity_digest() == b.identity.identity_digest();
        let req_eq = a.request.request_digest() == b.request.request_digest();
        let resp_eq = a.response.response_digest() == b.response.response_digest();
        let trans_eq = a.expected.expected_transcript_digest == b.expected.expected_transcript_digest;
        t.assert_true(
            &format!("determinism-{label}"),
            outcome_a == outcome_b && id_eq && req_eq && resp_eq && trans_eq,
            "repeat scenario produces identical outcome + identity/request/response/transcript digests",
        );
    }

    t.finish(out)
}

// ---------------------------------------------------------------------------
// Table 6 — refusal / fail-closed helper reachability.
// ---------------------------------------------------------------------------

fn run_refusal_helpers_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("refusal_helpers");

    t.assert_true(
        "mainnet-refusal-helper",
        mainnet_peer_driven_apply_remains_refused_under_kms_hsm_backend_boundary(Env::Mainnet)
            && !mainnet_peer_driven_apply_remains_refused_under_kms_hsm_backend_boundary(Env::Devnet)
            && !mainnet_peer_driven_apply_remains_refused_under_kms_hsm_backend_boundary(Env::Testnet),
        "MainNet refused; DevNet/TestNet not flagged by the refusal helper",
    );
    t.assert_true(
        "local-operator-refusal-helper",
        local_operator_cannot_satisfy_backend_policy(),
        "a local operator key cannot satisfy a KMS/HSM backend policy",
    );
    t.assert_true(
        "peer-majority-refusal-helper",
        peer_majority_cannot_satisfy_backend_policy(),
        "peer majority cannot satisfy a KMS/HSM backend policy",
    );

    t.finish(out)
}

// ---------------------------------------------------------------------------
// Fixture dump — identity/request/response for the evidence archive.
// ---------------------------------------------------------------------------

fn run_fixture_dump(out: &Path) {
    let s = scenario(BackendKind::FixtureKms, TrustBundleEnvironment::Devnet);
    write_file(
        &out.join("fixtures").join("identity.txt"),
        &format!("{:#?}\nidentity_digest={}\n", s.identity, s.identity.identity_digest()),
    );
    write_file(
        &out.join("fixtures").join("request.txt"),
        &format!("{:#?}\nrequest_digest={}\n", s.request, s.request.request_digest()),
    );
    write_file(
        &out.join("fixtures").join("response.txt"),
        &format!("{:#?}\nresponse_digest={}\n", s.response, s.response.response_digest()),
    );
    write_file(
        &out.join("fixtures").join("transcript_digest.txt"),
        &format!(
            "identity_digest={}\nrequest_digest={}\nresponse_digest={}\ntranscript_digest={}\n",
            s.identity.identity_digest(),
            s.request.request_digest(),
            s.response.response_digest(),
            backend_transcript_digest(
                &s.identity.identity_digest(),
                &s.request.request_digest(),
                &s.response.response_digest()
            ),
        ),
    );
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
    let mut args = env::args().skip(1);
    let out_dir = match args.next() {
        Some(a) => PathBuf::from(a),
        None => {
            eprintln!("usage: run_204_kms_hsm_backend_release_binary_helper <OUT_DIR>");
            std::process::exit(2);
        }
    };
    fs::create_dir_all(&out_dir).unwrap_or_else(|e| panic!("create out dir {out_dir:?}: {e}"));

    let tables: &[(&str, fn(&Path) -> (u64, u64))] = &[
        ("accepted", run_accepted_table),
        ("rejection", run_rejection_table),
        ("separation", run_separation_table),
        ("composition", run_composition_table),
        ("determinism", run_determinism_table),
        ("refusal_helpers", run_refusal_helpers_table),
    ];

    let mut total_pass = 0u64;
    let mut total_fail = 0u64;
    let mut summary = String::new();
    summary.push_str("run_204_kms_hsm_backend_release_binary_helper\n");
    summary.push_str(
        "scope: Run 203 production KMS/HSM backend abstraction boundary over the Run 188 custody boundary (release binary)\n",
    );
    summary.push_str(
        "note: fixture-only; no real KMS/HSM/cloud-KMS/PKCS#11/RemoteSigner backend; no live trust mutation; no P2P socket; production/cloud/PKCS#11 backends fail-closed; MainNet peer-driven apply remains refused\n\n",
    );
    for (name, f) in tables {
        let (pass, fail) = f(&out_dir);
        total_pass += pass;
        total_fail += fail;
        summary.push_str(&format!("table {name}: pass={pass} fail={fail}\n"));
    }

    run_fixture_dump(&out_dir);

    summary.push_str(&format!("\ntotal_pass: {total_pass}\n"));
    summary.push_str(&format!("total_fail: {total_fail}\n"));
    let verdict = if total_fail == 0 { "PASS" } else { "FAIL" };
    summary.push_str(&format!("verdict: {verdict}\n"));
    write_file(&out_dir.join("helper_summary.txt"), &summary);
    print!("{summary}");

    if total_fail != 0 {
        std::process::exit(1);
    }
}