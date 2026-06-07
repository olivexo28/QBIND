//! Run 202 — release-built helper that exercises the Run 201 production
//! **RemoteSigner transport boundary**
//! ([`qbind_node::pqc_remote_signer_transport`]) **in release mode**,
//! through the production library symbols, layered over the Run 194
//! RemoteSigner boundary ([`qbind_node::pqc_remote_authority_signer`]).
//!
//! Per `task/RUN_202_TASK.txt`, Run 202 is the release-binary evidence
//! run for the Run 201 source/test RemoteSigner transport boundary. This
//! helper is fixture-only tooling and:
//!
//! * does NOT modify any production runtime code, CLI flag, env var, wire
//!   / marker / sequence / trust-bundle / peer-candidate-envelope schema
//!   beyond what Runs 070, 130–201 already established;
//! * does NOT enable MainNet peer-driven apply on any surface;
//! * does NOT mutate any live trust state, write any marker, advance any
//!   sequence, swap any live trust, evict any session, or invoke Run 070 —
//!   every transport, verifier, and composition function exercised here is
//!   a pure function returning an owned typed outcome;
//! * does NOT open any P2P socket and performs no network or signer I/O;
//! * does NOT implement any real RemoteSigner backend, networked signer
//!   daemon, real KMS, real HSM, cloud KMS, or PKCS#11 integration; the
//!   [`qbind_node::pqc_remote_signer_transport::ProductionRemoteSignerTransport`]
//!   always returns the typed `ProductionTransportUnavailable` (or its
//!   MainNet variant) reject;
//! * never elevates the DevNet/TestNet
//!   [`qbind_node::pqc_remote_signer_transport::FixtureLoopbackRemoteSignerTransport`]
//!   into MainNet production custody (MainNet peer-driven apply always
//!   refuses at the typed boundary);
//! * exists alongside (and does NOT replace) the Run 201 source/test target
//!   `crates/qbind-node/tests/run_201_remote_signer_transport_boundary_tests.rs`.
//!
//! The helper proves, in release mode through the production library
//! symbols:
//!
//! 1. fixture loopback transport remains DevNet/TestNet evidence-only;
//! 2. production transport remains unavailable/fail-closed;
//! 3. MainNet production transport remains unavailable/fail-closed;
//! 4. request, response, and transcript digests are deterministic and
//!    domain-bound;
//! 5. transport composes with the Run 194 RemoteSigner request/response;
//! 6. transport composes with the custody/RemoteSigner validation path;
//! 7. MainNet peer-driven apply remains refused;
//! 8. no real RemoteSigner backend / networked signer daemon / KMS / HSM /
//!    governance execution / validator-set rotation is claimed.
//!
//! Usage:
//! ```text
//! run_202_remote_signer_transport_release_binary_helper <OUT_DIR>
//! ```

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use qbind_ledger::BundleSigningRatificationV2Action;
use qbind_node::pqc_authority_custody::{
    AuthorityCustodyAttestation, AuthorityCustodyClass, AuthorityCustodyPolicy,
};
use qbind_node::pqc_authority_lifecycle::{
    AuthorityTrustDomain, LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use qbind_node::pqc_authority_state::{
    AuthorityStateUpdateSource, PersistentAuthorityStateRecordV2,
    PersistentAuthorityStateRecordVersioned,
};
use qbind_node::pqc_governance_authority::GovernanceAuthorityClass;
use qbind_node::pqc_remote_authority_signer::{
    validate_remote_signer, RemoteSignerExpectations, RemoteSignerIdentity, RemoteSignerMode,
    RemoteSignerOutcome, RemoteSignerPolicy, RemoteSignerRequest,
};
use qbind_node::pqc_remote_signer_transport::{
    custody_class_routes_to_remote_signer_transport, endpoint_is_well_formed,
    local_operator_cannot_satisfy_remote_signer_transport,
    mainnet_peer_driven_apply_remains_refused_under_remote_signer_transport_boundary,
    peer_majority_cannot_satisfy_remote_signer_transport, remote_signer_response_canonical_digest,
    send_remote_signer_request, transport_transcript_digest,
    validate_lifecycle_custody_remote_signer_and_transport, validate_remote_signer_transport,
    validate_remote_signer_transport_for_custody_class, FixtureLoopbackRemoteSignerTransport,
    LifecycleCustodyRemoteSignerTransportOutcome, ProductionRemoteSignerTransport,
    RemoteSignerTransport, RemoteSignerTransportConfig, RemoteSignerTransportExpectations,
    RemoteSignerTransportOutcome, RemoteSignerTransportRequestEnvelope,
    RemoteSignerTransportResponseEnvelope, SimulatedTransportFault, TransportTimeoutRetryPolicy,
    REMOTE_SIGNER_TRANSPORT_INVALID_ATTESTATION_SENTINEL,
    REMOTE_SIGNER_TRANSPORT_PROTOCOL_VERSION,
    REMOTE_SIGNER_TRANSPORT_REQUEST_ENVELOPE_DOMAIN_TAG,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ---------------------------------------------------------------------------
// Constants — kept structurally identical to the Run 201 source/test
// fixtures so the typed RemoteSigner transport semantics carry over
// end-to-end in release mode.
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
const CUSTODY_ATTEST_DIGEST: &str = "custody-att-digest-202";
const CUSTODY_KEY_ID: &str = "custody-key-id-202";
const SIGNER_ID: &str = "remote-signer-202";
const SIGNER_PUBID: &str = "remote-signer-pubid-202";
const ATTEST_DIGEST: &str = "remote-signer-attest-202";
const REQ_NONCE: &str = "req-nonce-202";
const RESP_NONCE: &str = "resp-nonce-202";
const ENDPOINT: &str = "qbind-signer://signer.example:8443";
const SIGNER_IDENTITY_DIGEST: &str = "signer-identity-digest-202";
const TRANSPORT_ATTEST: &str = "transport-attest-202";
const REQUEST_ID: &str = "transport-request-id-202";
const PAYLOAD_DIGEST: &str = "transport-payload-digest-202";
const TRANSPORT_NONCE: &str = "transport-nonce-202";
const NOW: u64 = 1_700_000_000;
const FRESH: u64 = 1_699_999_900;
const EXPIRES: u64 = 1_700_001_000;

// ---------------------------------------------------------------------------
// Fixture builders — mirror the Run 201 source/test corpus.
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

fn identity(env: TrustBundleEnvironment) -> RemoteSignerIdentity {
    RemoteSignerIdentity {
        signer_id: SIGNER_ID.to_string(),
        signer_public_identity: SIGNER_PUBID.to_string(),
        custody_key_id: CUSTODY_KEY_ID.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        bundle_signing_key_fingerprint: KEY_B.to_string(),
        environment: env,
        chain_id: CHAIN_ID.to_string(),
        genesis_hash: GENESIS_HASH.to_string(),
        supported_suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        supported_lifecycle_actions: vec![
            LocalLifecycleAction::Rotate,
            LocalLifecycleAction::ActivateInitial,
        ],
        attestation_digest: ATTEST_DIGEST.to_string(),
        freshness_unix: Some(FRESH),
        expires_at_unix: Some(EXPIRES),
    }
}

fn inner_request(env: TrustBundleEnvironment) -> RemoteSignerRequest {
    RemoteSignerRequest {
        environment: env,
        chain_id: CHAIN_ID.to_string(),
        genesis_hash: GENESIS_HASH.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        lifecycle_action: LocalLifecycleAction::Rotate,
        candidate_digest: DIGEST_2.to_string(),
        authority_domain_sequence: 2,
        active_signing_key_fingerprint: Some(KEY_A.to_string()),
        new_signing_key_fingerprint: Some(KEY_B.to_string()),
        revoked_signing_key_fingerprint: None,
        governance_proof_digest: None,
        custody_attestation_digest: CUSTODY_ATTEST_DIGEST.to_string(),
        replay_nonce: REQ_NONCE.to_string(),
        request_timestamp_unix: Some(NOW),
    }
}

fn rs_expectations() -> RemoteSignerExpectations {
    RemoteSignerExpectations {
        expected_lifecycle_action: LocalLifecycleAction::Rotate,
        expected_candidate_digest: DIGEST_2.to_string(),
        expected_authority_domain_sequence: 2,
        expected_custody_key_id: CUSTODY_KEY_ID.to_string(),
        expected_signing_key_fingerprint: KEY_B.to_string(),
        expected_custody_attestation_digest: CUSTODY_ATTEST_DIGEST.to_string(),
        expected_request_nonce: REQ_NONCE.to_string(),
        expected_response_nonce: RESP_NONCE.to_string(),
        now_unix: NOW,
    }
}

fn transport_config(env: TrustBundleEnvironment) -> RemoteSignerTransportConfig {
    RemoteSignerTransportConfig {
        endpoint: ENDPOINT.to_string(),
        signer_id: SIGNER_ID.to_string(),
        custody_key_id: CUSTODY_KEY_ID.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        bundle_signing_key_fingerprint: KEY_B.to_string(),
        environment: env,
        chain_id: CHAIN_ID.to_string(),
        genesis_hash: GENESIS_HASH.to_string(),
        suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        expected_signer_identity_digest: SIGNER_IDENTITY_DIGEST.to_string(),
        transport_attestation_digest: Some(TRANSPORT_ATTEST.to_string()),
        timeout_retry: TransportTimeoutRetryPolicy::default(),
    }
}

fn transport_expectations() -> RemoteSignerTransportExpectations {
    RemoteSignerTransportExpectations {
        expected_request_id: REQUEST_ID.to_string(),
        expected_payload_digest: PAYLOAD_DIGEST.to_string(),
        expected_anti_replay_nonce: TRANSPORT_NONCE.to_string(),
        expected_signer_identity_digest: SIGNER_IDENTITY_DIGEST.to_string(),
        expected_transport_attestation_digest: Some(TRANSPORT_ATTEST.to_string()),
        now_unix: NOW,
    }
}

fn request_envelope(env: TrustBundleEnvironment) -> RemoteSignerTransportRequestEnvelope {
    let inner = inner_request(env);
    let canonical = inner.canonical_digest();
    RemoteSignerTransportRequestEnvelope {
        protocol_version: REMOTE_SIGNER_TRANSPORT_PROTOCOL_VERSION,
        domain_tag: REMOTE_SIGNER_TRANSPORT_REQUEST_ENVELOPE_DOMAIN_TAG.to_string(),
        request_id: REQUEST_ID.to_string(),
        timestamp_unix: NOW,
        environment: env,
        chain_id: CHAIN_ID.to_string(),
        genesis_hash: GENESIS_HASH.to_string(),
        authority_root_fingerprint: ROOT_FP.to_string(),
        custody_key_id: CUSTODY_KEY_ID.to_string(),
        expected_signer_id: SIGNER_ID.to_string(),
        canonical_request_digest: canonical,
        payload_digest: PAYLOAD_DIGEST.to_string(),
        anti_replay_nonce: TRANSPORT_NONCE.to_string(),
        inner_request: inner,
    }
}

fn fixture_transport(env: TrustBundleEnvironment) -> FixtureLoopbackRemoteSignerTransport {
    FixtureLoopbackRemoteSignerTransport {
        config: transport_config(env),
        identity: identity(env),
        response_nonce: RESP_NONCE.to_string(),
        response_freshness_unix: Some(FRESH),
        response_expires_at_unix: Some(EXPIRES),
        response_timestamp_unix: FRESH,
        response_expiry_unix: EXPIRES,
        simulated_fault: None,
    }
}

fn good_custody_attestation(
    env: TrustBundleEnvironment,
    candidate: &PersistentAuthorityStateRecordV2,
    class: AuthorityCustodyClass,
) -> AuthorityCustodyAttestation {
    AuthorityCustodyAttestation {
        custody_class: class,
        custody_key_id: CUSTODY_KEY_ID.to_string(),
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

/// A complete, valid accepted transport scenario for `env`.
#[derive(Clone)]
struct Scenario {
    domain: AuthorityTrustDomain,
    config: RemoteSignerTransportConfig,
    identity: RemoteSignerIdentity,
    request_env: RemoteSignerTransportRequestEnvelope,
    response_env: RemoteSignerTransportResponseEnvelope,
    rs_expected: RemoteSignerExpectations,
    transport_expected: RemoteSignerTransportExpectations,
}

fn scenario(env: TrustBundleEnvironment) -> Scenario {
    let transport = fixture_transport(env);
    let request_env = request_envelope(env);
    let response_env = transport
        .call_remote_signer(&request_env)
        .expect("fixture loopback transport returns a response");
    Scenario {
        domain: domain(env),
        config: transport_config(env),
        identity: identity(env),
        request_env,
        response_env,
        rs_expected: rs_expectations(),
        transport_expected: transport_expectations(),
    }
}

fn validate(s: &Scenario, policy: RemoteSignerPolicy) -> RemoteSignerTransportOutcome {
    validate_remote_signer_transport(
        &s.config,
        &s.request_env,
        &s.response_env,
        &s.domain,
        &s.identity,
        &s.rs_expected,
        &s.transport_expected,
        policy,
    )
}

fn validate_fixture(s: &Scenario) -> RemoteSignerTransportOutcome {
    validate(s, RemoteSignerPolicy::FixtureLoopbackAllowed)
}

/// Build a production-mode response envelope (signer_mode = Production)
/// by replacing the inner response. Used for the production-unavailable
/// vectors.
fn production_mode_response(s: &Scenario) -> RemoteSignerTransportResponseEnvelope {
    let mut env = s.response_env.clone();
    env.inner_response.signer_mode = RemoteSignerMode::Production;
    env
}

// ---------------------------------------------------------------------------
// Typed-outcome tagging — short, stable strings for the evidence tables.
// ---------------------------------------------------------------------------

fn transport_tag(outcome: &RemoteSignerTransportOutcome) -> String {
    use RemoteSignerTransportOutcome as O;
    let name = match outcome {
        O::FixtureLoopbackTransportAccepted { .. } => "accept:FixtureLoopbackTransportAccepted",
        O::TransportDisabled => "reject:TransportDisabled",
        O::FixtureTransportRejectedProductionRequired => {
            "reject:FixtureTransportRejectedProductionRequired"
        }
        O::FixtureTransportRejectedMainnetProductionRequired => {
            "reject:FixtureTransportRejectedMainnetProductionRequired"
        }
        O::ProductionTransportUnavailable => "reject:ProductionTransportUnavailable",
        O::MainNetProductionTransportUnavailable => "reject:MainNetProductionTransportUnavailable",
        O::FixtureLoopbackTransportRejectedForMainNet => {
            "reject:FixtureLoopbackTransportRejectedForMainNet"
        }
        O::EndpointMissing => "reject:EndpointMissing",
        O::EndpointMalformed { .. } => "reject:EndpointMalformed",
        O::WrongEnvironment { .. } => "reject:WrongEnvironment",
        O::WrongChain { .. } => "reject:WrongChain",
        O::WrongGenesis { .. } => "reject:WrongGenesis",
        O::WrongAuthorityRoot { .. } => "reject:WrongAuthorityRoot",
        O::WrongSignerId { .. } => "reject:WrongSignerId",
        O::WrongCustodyKeyId { .. } => "reject:WrongCustodyKeyId",
        O::WrongSigningKeyFingerprint { .. } => "reject:WrongSigningKeyFingerprint",
        O::WrongRequestId { .. } => "reject:WrongRequestId",
        O::WrongRequestDigest { .. } => "reject:WrongRequestDigest",
        O::WrongResponseDigest { .. } => "reject:WrongResponseDigest",
        O::WrongTranscriptDigest { .. } => "reject:WrongTranscriptDigest",
        O::StaleOrReplayedRequest { .. } => "reject:StaleOrReplayedRequest",
        O::StaleOrReplayedResponse { .. } => "reject:StaleOrReplayedResponse",
        O::Timeout => "reject:Timeout",
        O::RetryExhausted => "reject:RetryExhausted",
        O::MalformedRequestEnvelope { .. } => "reject:MalformedRequestEnvelope",
        O::MalformedResponseEnvelope { .. } => "reject:MalformedResponseEnvelope",
        O::UnsupportedProtocolVersion { .. } => "reject:UnsupportedProtocolVersion",
        O::UnsupportedSuite { .. } => "reject:UnsupportedSuite",
        O::InvalidTransportAttestation => "reject:InvalidTransportAttestation",
        O::LocalOperatorCannotSatisfyTransport => "reject:LocalOperatorCannotSatisfyTransport",
        O::PeerMajorityCannotSatisfyTransport => "reject:PeerMajorityCannotSatisfyTransport",
        O::RemoteSignerResponseInvalid { .. } => "reject:RemoteSignerResponseInvalid",
        O::NotRemoteSignerCustodyClass { .. } => "reject:NotRemoteSignerCustodyClass",
    };
    name.to_string()
}

fn composition_tag(outcome: &LifecycleCustodyRemoteSignerTransportOutcome) -> String {
    use LifecycleCustodyRemoteSignerTransportOutcome as O;
    match outcome {
        O::Accepted { .. } => "accept:Accepted",
        O::LifecycleCustodyOrRemoteSignerRejected(_) => {
            "reject:LifecycleCustodyOrRemoteSignerRejected"
        }
        O::TransportRejected { .. } => "reject:TransportRejected",
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
// Table 1 — accepted / compatible cases A1..A10.
// ---------------------------------------------------------------------------

fn run_accepted_table(out: &Path) -> (u64, u64) {
    let mut t = Table::new("accepted");

    // A1 — fixture loopback transport accepted on DevNet.
    let dev = scenario(TrustBundleEnvironment::Devnet);
    t.check("A1", "accept:FixtureLoopbackTransportAccepted", &transport_tag(&validate_fixture(&dev)));

    // A2 — fixture loopback transport accepted on TestNet.
    let test = scenario(TrustBundleEnvironment::Testnet);
    t.check("A2", "accept:FixtureLoopbackTransportAccepted", &transport_tag(&validate_fixture(&test)));

    // A3 — request envelope digest deterministic + domain-bound.
    let a = request_envelope(TrustBundleEnvironment::Devnet);
    let b = request_envelope(TrustBundleEnvironment::Devnet);
    let mut c = request_envelope(TrustBundleEnvironment::Devnet);
    c.request_id = "different".to_string();
    t.assert_true(
        "A3",
        a.envelope_digest() == b.envelope_digest() && a.envelope_digest() != c.envelope_digest(),
        "request envelope digest stable + changes when a bound field changes",
    );

    // A4 — response envelope digest deterministic + domain-bound.
    let s1 = scenario(TrustBundleEnvironment::Devnet);
    let s2 = scenario(TrustBundleEnvironment::Devnet);
    let mut other = s1.response_env.clone();
    other.signer_id = "other-signer".to_string();
    t.assert_true(
        "A4",
        s1.response_env.envelope_digest() == s2.response_env.envelope_digest()
            && s1.response_env.envelope_digest() != other.envelope_digest(),
        "response envelope digest stable + changes when a bound field changes",
    );

    // A5 — request/response transcript digest deterministic + order-sensitive.
    let req_d = dev.request_env.envelope_digest();
    let resp_d = dev.response_env.envelope_digest();
    let trans = transport_transcript_digest(&req_d, &resp_d);
    t.assert_true(
        "A5",
        trans == transport_transcript_digest(&req_d, &resp_d)
            && dev.response_env.transcript_digest == trans
            && trans != transport_transcript_digest(&resp_d, &req_d),
        "transcript digest stable, bound by fixture, order-sensitive",
    );

    // A6 — transport request binds the full authority tuple + sequence.
    let r = &dev.request_env;
    t.assert_true(
        "A6",
        r.environment == TrustBundleEnvironment::Devnet
            && r.chain_id == CHAIN_ID
            && r.genesis_hash == GENESIS_HASH
            && r.authority_root_fingerprint == ROOT_FP
            && r.expected_signer_id == SIGNER_ID
            && r.custody_key_id == CUSTODY_KEY_ID
            && r.inner_request.lifecycle_action == LocalLifecycleAction::Rotate
            && r.inner_request.candidate_digest == DIGEST_2
            && r.inner_request.authority_domain_sequence == 2
            && r.canonical_request_digest == r.inner_request.canonical_digest(),
        "request binds env/chain/genesis/root/signer/custody/action/candidate/sequence",
    );

    // A7 — transport response binds request id, digests, transcript.
    let resp = &dev.response_env;
    let expected_transcript =
        transport_transcript_digest(&dev.request_env.envelope_digest(), &resp.envelope_digest());
    t.assert_true(
        "A7",
        resp.request_id_echo == REQUEST_ID
            && resp.signer_id == SIGNER_ID
            && resp.custody_key_id == CUSTODY_KEY_ID
            && resp.inner_response.request_digest == dev.request_env.inner_request.canonical_digest()
            && resp.canonical_response_digest
                == remote_signer_response_canonical_digest(&resp.inner_response)
            && resp.transcript_digest == expected_transcript,
        "response binds request id, request/response digest, transcript digest",
    );

    // A8 — production transport boundary callable + typed unavailable.
    let prod = ProductionRemoteSignerTransport {
        config: transport_config(TrustBundleEnvironment::Devnet),
    };
    let req = request_envelope(TrustBundleEnvironment::Devnet);
    t.assert_true(
        "A8",
        prod.call_remote_signer(&req)
            == Err(RemoteSignerTransportOutcome::ProductionTransportUnavailable)
            && send_remote_signer_request(&prod, &req)
                == Err(RemoteSignerTransportOutcome::ProductionTransportUnavailable),
        "production transport callable, fails closed unavailable (direct + free helper)",
    );

    // A9 — Run 194 validation compatible with the fixture transport response.
    let inner = validate_remote_signer(
        &dev.identity,
        &dev.request_env.inner_request,
        &dev.response_env.inner_response,
        &dev.domain,
        &dev.rs_expected,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
    );
    t.assert_true(
        "A9",
        matches!(inner, RemoteSignerOutcome::FixtureLoopbackAccepted { .. }),
        "Run 194 verifier accepts the wrapped fixture request/response",
    );

    // A10 — disabled transport policy does not disturb inner governance.
    let disabled = validate(&dev, RemoteSignerPolicy::Disabled);
    let inner2 = validate_remote_signer(
        &dev.identity,
        &dev.request_env.inner_request,
        &dev.response_env.inner_response,
        &dev.domain,
        &dev.rs_expected,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
    );
    t.assert_true(
        "A10",
        disabled == RemoteSignerTransportOutcome::TransportDisabled
            && matches!(inner2, RemoteSignerOutcome::FixtureLoopbackAccepted { .. }),
        "transport disabled fails closed yet Run 194 GenesisBound behaviour unchanged",
    );

    t.finish(out)
}

// ---------------------------------------------------------------------------
// Table 2 — rejection cases R1..R35.
// ---------------------------------------------------------------------------

fn run_rejection_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("rejection");
    let dev = || scenario(Env::Devnet);

    // R1 — Disabled policy.
    t.check("R1", "reject:TransportDisabled", &transport_tag(&validate(&dev(), RemoteSignerPolicy::Disabled)));

    // R2 — fixture rejected under ProductionRemoteSignerRequired.
    t.check(
        "R2",
        "reject:FixtureTransportRejectedProductionRequired",
        &transport_tag(&validate(&dev(), RemoteSignerPolicy::ProductionRemoteSignerRequired)),
    );

    // R3 — fixture rejected under MainnetProductionRemoteSignerRequired.
    t.check(
        "R3",
        "reject:FixtureTransportRejectedMainnetProductionRequired",
        &transport_tag(&validate(&dev(), RemoteSignerPolicy::MainnetProductionRemoteSignerRequired)),
    );

    // R4 — production transport unavailable (production-mode response).
    {
        let base = dev();
        let mut s = dev();
        s.response_env = production_mode_response(&base);
        t.check("R4", "reject:ProductionTransportUnavailable", &transport_tag(&validate_fixture(&s)));
    }

    // R5 — MainNet production transport unavailable.
    {
        let prod = ProductionRemoteSignerTransport {
            config: transport_config(Env::Mainnet),
        };
        let req = request_envelope(Env::Mainnet);
        let direct = prod.call_remote_signer(&req)
            == Err(RemoteSignerTransportOutcome::MainNetProductionTransportUnavailable);
        let base = dev();
        let mut s = dev();
        s.response_env = production_mode_response(&base);
        let via = validate(&s, RemoteSignerPolicy::MainnetProductionRemoteSignerRequired);
        t.assert_true(
            "R5",
            direct && via == RemoteSignerTransportOutcome::MainNetProductionTransportUnavailable,
            "MainNet production transport unavailable (direct + via validator)",
        );
    }

    // R6 — endpoint missing.
    {
        let mut s = dev();
        s.config.endpoint = String::new();
        t.check("R6", "reject:EndpointMissing", &transport_tag(&validate_fixture(&s)));
    }

    // R7 — endpoint malformed.
    {
        let mut s = dev();
        s.config.endpoint = "no-scheme-here".to_string();
        t.check("R7", "reject:EndpointMalformed", &transport_tag(&validate_fixture(&s)));
    }

    // R8 — wrong environment (TestNet scenario against DevNet domain).
    {
        let s = scenario(Env::Testnet);
        let dev_domain = domain(Env::Devnet);
        let outcome = validate_remote_signer_transport(
            &s.config,
            &s.request_env,
            &s.response_env,
            &dev_domain,
            &s.identity,
            &s.rs_expected,
            &s.transport_expected,
            RemoteSignerPolicy::FixtureLoopbackAllowed,
        );
        t.check("R8", "reject:WrongEnvironment", &transport_tag(&outcome));
    }

    // R9 — wrong chain.
    {
        let mut s = dev();
        s.config.chain_id = OTHER_CHAIN.to_string();
        t.check("R9", "reject:WrongChain", &transport_tag(&validate_fixture(&s)));
    }

    // R10 — wrong genesis.
    {
        let mut s = dev();
        s.config.genesis_hash = OTHER_GENESIS.to_string();
        t.check("R10", "reject:WrongGenesis", &transport_tag(&validate_fixture(&s)));
    }

    // R11 — wrong signer id.
    {
        let mut s = dev();
        s.config.signer_id = "wrong-signer".to_string();
        t.check("R11", "reject:WrongSignerId", &transport_tag(&validate_fixture(&s)));
    }

    // R12 — wrong custody key id.
    {
        let mut s = dev();
        s.config.custody_key_id = "wrong-custody".to_string();
        t.check("R12", "reject:WrongCustodyKeyId", &transport_tag(&validate_fixture(&s)));
    }

    // R13 — wrong authority root.
    {
        let mut s = dev();
        s.config.authority_root_fingerprint = OTHER_ROOT_FP.to_string();
        t.check("R13", "reject:WrongAuthorityRoot", &transport_tag(&validate_fixture(&s)));
    }

    // R14 — wrong signing-key fingerprint.
    {
        let mut s = dev();
        s.config.bundle_signing_key_fingerprint = KEY_A.to_string();
        t.check("R14", "reject:WrongSigningKeyFingerprint", &transport_tag(&validate_fixture(&s)));
    }

    // R15 — wrong request id.
    {
        let mut s = dev();
        s.response_env.request_id_echo = "wrong-echo".to_string();
        t.check("R15", "reject:WrongRequestId", &transport_tag(&validate_fixture(&s)));
    }

    // R16 — wrong request digest.
    {
        let mut s = dev();
        s.request_env.canonical_request_digest = "deadbeef".to_string();
        t.check("R16", "reject:WrongRequestDigest", &transport_tag(&validate_fixture(&s)));
    }

    // R17 — wrong response digest.
    {
        let mut s = dev();
        s.response_env.canonical_response_digest = "deadbeef".to_string();
        t.check("R17", "reject:WrongResponseDigest", &transport_tag(&validate_fixture(&s)));
    }

    // R18 — wrong transcript digest.
    {
        let mut s = dev();
        s.response_env.transcript_digest = "deadbeef".to_string();
        t.check("R18", "reject:WrongTranscriptDigest", &transport_tag(&validate_fixture(&s)));
    }

    // R19 — stale/replayed request.
    {
        let mut s = dev();
        s.request_env.anti_replay_nonce = "stale-nonce".to_string();
        t.check("R19", "reject:StaleOrReplayedRequest", &transport_tag(&validate_fixture(&s)));
    }

    // R20 — stale/replayed response (now beyond expiry).
    {
        let mut s = dev();
        s.transport_expected.now_unix = EXPIRES + 1;
        s.rs_expected.now_unix = EXPIRES + 1;
        t.check("R20", "reject:StaleOrReplayedResponse", &transport_tag(&validate_fixture(&s)));
    }

    // R21 — timeout (simulated transport fault at the trait boundary).
    {
        let mut transport = fixture_transport(Env::Devnet);
        transport.simulated_fault = Some(SimulatedTransportFault::Timeout);
        let req = request_envelope(Env::Devnet);
        let got = transport
            .call_remote_signer(&req)
            .err()
            .map(|o| transport_tag(&o))
            .unwrap_or_else(|| "accept:unexpected".to_string());
        t.check("R21", "reject:Timeout", &got);
    }

    // R22 — retry exhausted.
    {
        let mut transport = fixture_transport(Env::Devnet);
        transport.simulated_fault = Some(SimulatedTransportFault::RetryExhausted);
        let req = request_envelope(Env::Devnet);
        let got = transport
            .call_remote_signer(&req)
            .err()
            .map(|o| transport_tag(&o))
            .unwrap_or_else(|| "accept:unexpected".to_string());
        t.check("R22", "reject:RetryExhausted", &got);
    }

    // R23 — malformed request envelope.
    {
        let mut s = dev();
        s.request_env.request_id = String::new();
        t.check("R23", "reject:MalformedRequestEnvelope", &transport_tag(&validate_fixture(&s)));
    }

    // R24 — malformed response envelope.
    {
        let mut s = dev();
        s.response_env.response_commitment = String::new();
        t.check("R24", "reject:MalformedResponseEnvelope", &transport_tag(&validate_fixture(&s)));
    }

    // R25 — unsupported protocol version.
    {
        let mut s = dev();
        s.request_env.protocol_version = 99;
        t.check("R25", "reject:UnsupportedProtocolVersion", &transport_tag(&validate_fixture(&s)));
    }

    // R26 — unsupported suite.
    {
        let mut s = dev();
        s.config.suite_id = 7;
        t.check("R26", "reject:UnsupportedSuite", &transport_tag(&validate_fixture(&s)));
    }

    // R27 — invalid transport attestation.
    {
        let mut s = dev();
        s.config.transport_attestation_digest =
            Some(REMOTE_SIGNER_TRANSPORT_INVALID_ATTESTATION_SENTINEL.to_string());
        t.check("R27", "reject:InvalidTransportAttestation", &transport_tag(&validate_fixture(&s)));
    }

    // R28 — local operator cannot satisfy transport.
    {
        let s = dev();
        let outcome = validate_remote_signer_transport_for_custody_class(
            AuthorityCustodyClass::LocalOperatorKey,
            &s.config,
            &s.request_env,
            &s.response_env,
            &s.domain,
            &s.identity,
            &s.rs_expected,
            &s.transport_expected,
            RemoteSignerPolicy::FixtureLoopbackAllowed,
        );
        t.assert_true(
            "R28",
            outcome == RemoteSignerTransportOutcome::LocalOperatorCannotSatisfyTransport
                && local_operator_cannot_satisfy_remote_signer_transport(),
            "local operator key routes to LocalOperatorCannotSatisfyTransport",
        );
    }

    // R29 — peer majority cannot satisfy transport.
    t.assert_true(
        "R29",
        peer_majority_cannot_satisfy_remote_signer_transport()
            && RemoteSignerTransportOutcome::PeerMajorityCannotSatisfyTransport.is_reject(),
        "peer majority cannot satisfy a remote signer transport",
    );

    // R30 — transport valid but RemoteSigner response invalid.
    {
        let mut s = dev();
        s.rs_expected.expected_response_nonce = "wrong-response-nonce".to_string();
        t.check("R30", "reject:RemoteSignerResponseInvalid", &transport_tag(&validate_fixture(&s)));
    }

    // R31 — RemoteSigner valid but transport transcript invalid.
    {
        let mut s = dev();
        s.response_env.transcript_digest =
            transport_transcript_digest("not-the-request", "not-the-response");
        t.check("R31", "reject:WrongTranscriptDigest", &transport_tag(&validate_fixture(&s)));
    }

    // R32 — lifecycle/governance/custody valid but production transport unavailable.
    {
        let s = dev();
        let inner = validate_remote_signer(
            &s.identity,
            &s.request_env.inner_request,
            &s.response_env.inner_response,
            &s.domain,
            &s.rs_expected,
            RemoteSignerPolicy::FixtureLoopbackAllowed,
        );
        let prod = ProductionRemoteSignerTransport {
            config: transport_config(Env::Devnet),
        };
        t.assert_true(
            "R32",
            matches!(inner, RemoteSignerOutcome::FixtureLoopbackAccepted { .. })
                && prod.call_remote_signer(&s.request_env)
                    == Err(RemoteSignerTransportOutcome::ProductionTransportUnavailable),
            "inner composition accepts fixture yet production transport fails closed",
        );
    }

    // R33 — validation-only rejection remains non-mutating.
    {
        let s = dev();
        let config_before = s.config.clone();
        let request_before = s.request_env.clone();
        let response_before = s.response_env.clone();
        let _ = validate(&s, RemoteSignerPolicy::Disabled);
        let mut s2 = dev();
        s2.config.chain_id = OTHER_CHAIN.to_string();
        let _ = validate_fixture(&s2);
        t.assert_true(
            "R33",
            s.config == config_before
                && s.request_env == request_before
                && s.response_env == response_before,
            "rejecting validation leaves all inputs byte-identical",
        );
    }

    // R34 — mutating preflight rejection produces no mutation.
    {
        let s = dev();
        let candidate = rotate_candidate(Env::Devnet);
        let prior = prior_versioned(Env::Devnet);
        let custody =
            good_custody_attestation(Env::Devnet, &candidate, AuthorityCustodyClass::FixtureLocalKey);
        let candidate_before = candidate.clone();
        let outcome = validate_lifecycle_custody_remote_signer_and_transport(
            &custody,
            &candidate,
            Some(&prior),
            &s.domain,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::Rotate,
            DIGEST_2,
            2,
            Some(CUSTODY_KEY_ID),
            AuthorityCustodyPolicy::DevnetLocalAllowed,
            &s.identity,
            &s.request_env.inner_request,
            &s.response_env.inner_response,
            &s.rs_expected,
            RemoteSignerPolicy::Disabled,
            &s.config,
            &s.request_env,
            &s.response_env,
            &s.transport_expected,
            NOW,
            false,
        );
        t.assert_true(
            "R34",
            outcome.is_reject() && candidate == candidate_before,
            "disabled-policy composition rejects without mutating the candidate",
        );
    }

    // R35 — MainNet peer-driven apply refused even with fixture loopback transport.
    {
        let s = scenario(Env::Mainnet);
        let candidate = rotate_candidate(Env::Mainnet);
        let prior = prior_versioned(Env::Mainnet);
        let custody = good_custody_attestation(
            Env::Mainnet,
            &candidate,
            AuthorityCustodyClass::FixtureLocalKey,
        );
        let outcome = validate_lifecycle_custody_remote_signer_and_transport(
            &custody,
            &candidate,
            Some(&prior),
            &s.domain,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::Rotate,
            DIGEST_2,
            2,
            Some(CUSTODY_KEY_ID),
            AuthorityCustodyPolicy::DevnetLocalAllowed,
            &s.identity,
            &s.request_env.inner_request,
            &s.response_env.inner_response,
            &s.rs_expected,
            RemoteSignerPolicy::FixtureLoopbackAllowed,
            &s.config,
            &s.request_env,
            &s.response_env,
            &s.transport_expected,
            NOW,
            true,
        );
        t.assert_true(
            "R35",
            outcome == LifecycleCustodyRemoteSignerTransportOutcome::MainNetPeerDrivenApplyRefused
                && mainnet_peer_driven_apply_remains_refused_under_remote_signer_transport_boundary(
                    Env::Mainnet,
                ),
            "MainNet peer-driven apply refused even with fixture loopback transport material",
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

    // Fixture loopback transport refused for MainNet.
    let main = scenario(Env::Mainnet);
    t.check(
        "fixture-rejected-mainnet",
        "reject:FixtureLoopbackTransportRejectedForMainNet",
        &transport_tag(&validate_fixture(&main)),
    );

    // Fixture vs production transport are distinct.
    let dev = scenario(Env::Devnet);
    let prod = ProductionRemoteSignerTransport {
        config: transport_config(Env::Devnet),
    };
    t.assert_true(
        "fixture-vs-production-distinct",
        dev.response_env.inner_response.signer_mode == RemoteSignerMode::FixtureLoopback
            && prod.call_remote_signer(&dev.request_env).is_err(),
        "fixture returns a fixture-mode response; production never returns a response",
    );

    // Production transport performs no I/O and fails closed on both DevNet/TestNet.
    let mut prod_ok = true;
    for env in [Env::Devnet, Env::Testnet] {
        let p = ProductionRemoteSignerTransport {
            config: transport_config(env),
        };
        let req = request_envelope(env);
        prod_ok &= p.call_remote_signer(&req)
            == Err(RemoteSignerTransportOutcome::ProductionTransportUnavailable);
    }
    t.assert_true(
        "production-no-io-fail-closed",
        prod_ok,
        "production transport returns typed unavailable on DevNet + TestNet, no I/O",
    );

    // Malformed envelope fails closed before a response is produced.
    {
        let transport = fixture_transport(Env::Devnet);
        let mut req = request_envelope(Env::Devnet);
        req.canonical_request_digest = String::new();
        t.assert_true(
            "malformed-fails-before-response",
            matches!(
                transport.call_remote_signer(&req),
                Err(RemoteSignerTransportOutcome::MalformedRequestEnvelope { .. })
            ),
            "fixture transport rejects a malformed request before building a response",
        );
    }

    // Endpoint helper matches the validator decision.
    t.assert_true(
        "endpoint-helper",
        endpoint_is_well_formed(ENDPOINT)
            && !endpoint_is_well_formed("")
            && !endpoint_is_well_formed("bad endpoint"),
        "endpoint_is_well_formed agrees with validator endpoint gating",
    );

    // Custody-class routing predicate + non-remote-signer class rejection.
    {
        let s = scenario(Env::Devnet);
        let outcome = validate_remote_signer_transport_for_custody_class(
            AuthorityCustodyClass::FixtureLocalKey,
            &s.config,
            &s.request_env,
            &s.response_env,
            &s.domain,
            &s.identity,
            &s.rs_expected,
            &s.transport_expected,
            RemoteSignerPolicy::FixtureLoopbackAllowed,
        );
        t.assert_true(
            "custody-class-routing",
            custody_class_routes_to_remote_signer_transport(AuthorityCustodyClass::RemoteSigner)
                && matches!(
                    outcome,
                    RemoteSignerTransportOutcome::NotRemoteSignerCustodyClass { .. }
                ),
            "RemoteSigner class routes in; a non-RemoteSigner class is rejected",
        );
    }

    // Trait object is mockable.
    {
        let transport = fixture_transport(Env::Devnet);
        let dynref: &dyn RemoteSignerTransport = &transport;
        let req = request_envelope(Env::Devnet);
        t.assert_true(
            "trait-object-mockable",
            dynref.call_remote_signer(&req).is_ok() && dynref.config().signer_id == SIGNER_ID,
            "RemoteSignerTransport is usable as a trait object",
        );
    }

    // Default policy is Disabled and fails closed even with a valid transport.
    {
        let s = scenario(Env::Devnet);
        t.check(
            "default-policy-disabled",
            "reject:TransportDisabled",
            &transport_tag(&validate(&s, RemoteSignerPolicy::default())),
        );
    }

    // Malformed timeout/retry policy fails the config well-formedness gate.
    {
        let mut s = scenario(Env::Devnet);
        s.config.timeout_retry = TransportTimeoutRetryPolicy {
            per_attempt_timeout_ms: 0,
            max_attempts: 0,
        };
        t.check(
            "malformed-timeout-retry",
            "reject:MalformedRequestEnvelope",
            &transport_tag(&validate_fixture(&s)),
        );
    }

    t.finish(out)
}

// ---------------------------------------------------------------------------
// Table 4 — full lifecycle/custody/remote-signer/transport composition.
// ---------------------------------------------------------------------------

fn run_composition_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("composition");

    let compose = |s: &Scenario,
                   candidate: &PersistentAuthorityStateRecordV2,
                   prior: &PersistentAuthorityStateRecordVersioned,
                   custody: &AuthorityCustodyAttestation,
                   policy: RemoteSignerPolicy,
                   peer_driven: bool|
     -> LifecycleCustodyRemoteSignerTransportOutcome {
        validate_lifecycle_custody_remote_signer_and_transport(
            custody,
            candidate,
            Some(prior),
            &s.domain,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::Rotate,
            DIGEST_2,
            2,
            Some(CUSTODY_KEY_ID),
            AuthorityCustodyPolicy::DevnetLocalAllowed,
            &s.identity,
            &s.request_env.inner_request,
            &s.response_env.inner_response,
            &s.rs_expected,
            policy,
            &s.config,
            &s.request_env,
            &s.response_env,
            &s.transport_expected,
            NOW,
            peer_driven,
        )
    };

    // Accepted full composition on DevNet.
    {
        let s = scenario(Env::Devnet);
        let candidate = rotate_candidate(Env::Devnet);
        let prior = prior_versioned(Env::Devnet);
        let custody =
            good_custody_attestation(Env::Devnet, &candidate, AuthorityCustodyClass::FixtureLocalKey);
        let outcome = compose(
            &s,
            &candidate,
            &prior,
            &custody,
            RemoteSignerPolicy::FixtureLoopbackAllowed,
            false,
        );
        t.check("compose-accept-devnet", "accept:Accepted", &composition_tag(&outcome));
    }

    // Inner accepts but transport boundary rejects (corrupt transcript).
    {
        let mut s = scenario(Env::Devnet);
        s.response_env.transcript_digest = "deadbeef".to_string();
        let candidate = rotate_candidate(Env::Devnet);
        let prior = prior_versioned(Env::Devnet);
        let custody =
            good_custody_attestation(Env::Devnet, &candidate, AuthorityCustodyClass::FixtureLocalKey);
        let outcome = compose(
            &s,
            &candidate,
            &prior,
            &custody,
            RemoteSignerPolicy::FixtureLoopbackAllowed,
            false,
        );
        t.check("compose-transport-rejected", "reject:TransportRejected", &composition_tag(&outcome));
    }

    // Disabled policy rejects the inner composition (no mutation).
    {
        let s = scenario(Env::Devnet);
        let candidate = rotate_candidate(Env::Devnet);
        let prior = prior_versioned(Env::Devnet);
        let custody =
            good_custody_attestation(Env::Devnet, &candidate, AuthorityCustodyClass::FixtureLocalKey);
        let outcome = compose(
            &s,
            &candidate,
            &prior,
            &custody,
            RemoteSignerPolicy::Disabled,
            false,
        );
        t.check(
            "compose-inner-rejected",
            "reject:LifecycleCustodyOrRemoteSignerRejected",
            &composition_tag(&outcome),
        );
    }

    // MainNet peer-driven apply refused even with fixture loopback transport.
    {
        let s = scenario(Env::Mainnet);
        let candidate = rotate_candidate(Env::Mainnet);
        let prior = prior_versioned(Env::Mainnet);
        let custody =
            good_custody_attestation(Env::Mainnet, &candidate, AuthorityCustodyClass::FixtureLocalKey);
        let outcome = compose(
            &s,
            &candidate,
            &prior,
            &custody,
            RemoteSignerPolicy::FixtureLoopbackAllowed,
            true,
        );
        t.check(
            "compose-mainnet-refused",
            "reject:MainNetPeerDrivenApplyRefused",
            &composition_tag(&outcome),
        );
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
        let a = scenario(env);
        let b = scenario(env);
        let outcome_a = transport_tag(&validate_fixture(&a));
        let outcome_b = transport_tag(&validate_fixture(&b));
        let req_eq = a.request_env.envelope_digest() == b.request_env.envelope_digest();
        let resp_eq = a.response_env.envelope_digest() == b.response_env.envelope_digest();
        let trans_eq = a.response_env.transcript_digest == b.response_env.transcript_digest;
        t.assert_true(
            &format!("determinism-{label}"),
            outcome_a == outcome_b && req_eq && resp_eq && trans_eq,
            "repeat scenario produces identical outcome + request/response/transcript digests",
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
        mainnet_peer_driven_apply_remains_refused_under_remote_signer_transport_boundary(Env::Mainnet)
            && !mainnet_peer_driven_apply_remains_refused_under_remote_signer_transport_boundary(
                Env::Devnet,
            )
            && !mainnet_peer_driven_apply_remains_refused_under_remote_signer_transport_boundary(
                Env::Testnet,
            ),
        "MainNet refused; DevNet/TestNet not flagged by the refusal helper",
    );
    t.assert_true(
        "local-operator-refusal-helper",
        local_operator_cannot_satisfy_remote_signer_transport(),
        "a local operator key cannot satisfy a remote signer transport",
    );
    t.assert_true(
        "peer-majority-refusal-helper",
        peer_majority_cannot_satisfy_remote_signer_transport(),
        "peer majority cannot satisfy a remote signer transport",
    );

    t.finish(out)
}

// ---------------------------------------------------------------------------
// Fixture dump — request/response envelopes for the evidence archive.
// ---------------------------------------------------------------------------

fn run_fixture_dump(out: &Path) {
    let s = scenario(TrustBundleEnvironment::Devnet);
    write_file(
        &out.join("fixtures").join("request_envelope.txt"),
        &format!(
            "{:#?}\nenvelope_digest={}\n",
            s.request_env,
            s.request_env.envelope_digest()
        ),
    );
    write_file(
        &out.join("fixtures").join("response_envelope.txt"),
        &format!(
            "{:#?}\nenvelope_digest={}\ntranscript_digest={}\n",
            s.response_env,
            s.response_env.envelope_digest(),
            s.response_env.transcript_digest
        ),
    );
    write_file(
        &out.join("fixtures").join("transcript_digest.txt"),
        &format!(
            "request_envelope_digest={}\nresponse_envelope_digest={}\ntranscript_digest={}\n",
            s.request_env.envelope_digest(),
            s.response_env.envelope_digest(),
            transport_transcript_digest(
                &s.request_env.envelope_digest(),
                &s.response_env.envelope_digest()
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
            eprintln!("usage: run_202_remote_signer_transport_release_binary_helper <OUT_DIR>");
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
    summary.push_str("run_202_remote_signer_transport_release_binary_helper\n");
    summary.push_str(
        "scope: Run 201 production RemoteSigner transport boundary over the Run 194 RemoteSigner boundary (release binary)\n",
    );
    summary.push_str(
        "note: fixture-only; no real RemoteSigner/networked signer daemon/KMS/HSM backend; no live trust mutation; no P2P socket; production transport fail-closed; MainNet peer-driven apply remains refused\n\n",
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