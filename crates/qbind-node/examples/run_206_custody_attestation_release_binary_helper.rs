//! Run 206 — release-built helper that exercises the Run 205 production
//! **custody attestation verifier boundary**
//! ([`qbind_node::pqc_custody_attestation_verifier`]) **in release mode**,
//! through the production library symbols, layered over the Run 188
//! authority custody boundary
//! ([`qbind_node::pqc_authority_custody`]).
//!
//! Per `task/RUN_206_TASK.txt`, Run 206 is the release-binary evidence
//! run for the Run 205 source/test custody attestation verifier skeleton.
//! This helper is fixture-only tooling and:
//!
//! * does NOT modify any production runtime code, CLI flag, env var, wire
//!   / marker / sequence / trust-bundle / peer-candidate-envelope schema
//!   beyond what Runs 070, 130–205 already established;
//! * does NOT enable MainNet peer-driven apply on any surface;
//! * does NOT mutate any live trust state, write any marker, advance any
//!   sequence, swap any live trust, evict any session, or invoke Run 070 —
//!   every verifier and composition function exercised here is a pure
//!   function returning an owned typed outcome;
//! * does NOT open any P2P socket and performs no network or backend I/O;
//! * does NOT implement any real cloud-KMS attestation verifier, real
//!   PKCS#11 attestation verifier, real HSM-vendor attestation verifier,
//!   real RemoteSigner attestation verifier, real KMS/HSM backend, or real
//!   RemoteSigner backend; the
//!   [`qbind_node::pqc_custody_attestation_verifier::ProductionAttestationVerifier`],
//!   [`qbind_node::pqc_custody_attestation_verifier::CloudKmsAttestationVerifier`],
//!   [`qbind_node::pqc_custody_attestation_verifier::Pkcs11HsmAttestationVerifier`],
//!   [`qbind_node::pqc_custody_attestation_verifier::HsmAttestationVerifier`],
//!   [`qbind_node::pqc_custody_attestation_verifier::KmsAttestationVerifier`], and
//!   [`qbind_node::pqc_custody_attestation_verifier::RemoteSignerAttestationVerifier`]
//!   always return the typed unavailable reject;
//! * never elevates the DevNet/TestNet
//!   [`qbind_node::pqc_custody_attestation_verifier::FixtureCustodyAttestationVerifier`]
//!   into MainNet production custody (MainNet peer-driven apply always
//!   refuses at the typed boundary);
//! * exists alongside (and does NOT replace) the Run 205 source/test
//!   target
//!   `crates/qbind-node/tests/run_205_custody_attestation_verifier_tests.rs`.
//!
//! The helper proves, in release mode through the production library
//! symbols:
//!
//! 1. fixture custody attestation remains DevNet/TestNet evidence-only;
//! 2. production/cloud-KMS/PKCS#11/HSM/RemoteSigner attestation verifiers
//!    remain unavailable/fail-closed;
//! 3. attestation evidence/input/transcript/provider-identity digests are
//!    deterministic and domain-bound;
//! 4. the attestation verifier composes with Run 188 custody metadata;
//! 5. the attestation verifier composes with the Run 201 RemoteSigner
//!    transport and Run 203 KMS/HSM backend boundaries (as opaque bound
//!    evidence) where feasible;
//! 6. rejected attestation cases produce no mutation;
//! 7. MainNet peer-driven apply remains refused;
//! 8. no real KMS/HSM attestation, RemoteSigner backend, governance
//!    execution, or validator-set rotation is claimed.
//!
//! Usage:
//! ```text
//! run_206_custody_attestation_release_binary_helper <OUT_DIR>
//! ```

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use qbind_ledger::BundleSigningRatificationV2Action;
use qbind_node::pqc_authority_custody::{
    AuthorityCustodyAttestation, AuthorityCustodyClass, AuthorityCustodyPolicy,
};
use qbind_node::pqc_authority_kms_hsm_backend::{backend_transcript_digest, BackendKind};
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

// ---------------------------------------------------------------------------
// Constants — kept structurally identical to the Run 205 source/test
// fixtures so the typed custody-attestation semantics carry over end-to-end
// in release mode.
// ---------------------------------------------------------------------------

const KEY_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEY_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ROOT_FP: &str = "1111111111111111111111111111111111111111";
const CHAIN_ID: &str = "0000000000000001";
const GENESIS_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const PRIOR_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const KEY_ID: &str = "attestation-key-id-206";
const PROVIDER_ID: &str = "attestation-provider-206";
const ATTEST_COMMITMENT: &str = "attestation-commitment-206";
const ATTEST_NONCE: &str = "attestation-nonce-206";
const GOV_PROOF_DIGEST: &str = "gov-proof-digest-206";
const NOW: u64 = 1_700_000_000;
const FRESH: u64 = 1_699_999_900;
const EXPIRES: u64 = 1_700_001_000;
const ISSUED: u64 = 1_699_999_950;
const WINDOW_SINCE: u64 = 1_699_999_000;
const WINDOW_UNTIL: u64 = 1_700_000_500;

// ---------------------------------------------------------------------------
// Fixture builders — mirror the Run 205 source/test corpus.
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

/// A bound Run 203 backend / Run 201 RemoteSigner transcript digest,
/// demonstrating composition with the KMS/HSM backend path (Run 203) and
/// the RemoteSigner transport path (Run 201) as opaque evidence fields.
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
        custody_attestation_digest: "custody-att-digest-206".to_string(),
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

/// A complete, valid accepted attestation scenario, returning every part a
/// check needs to mutate one field for a rejection vector.
#[derive(Clone)]
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
    Scenario { domain: domain(env), candidate, evidence, input }
}

fn verify(s: &Scenario, policy: CustodyAttestationPolicy) -> CustodyAttestationOutcome {
    verify_custody_attestation(&s.evidence, &s.input, &s.domain, policy)
}

// ---------------------------------------------------------------------------
// Typed-outcome tagging — short, stable strings for the evidence tables.
// ---------------------------------------------------------------------------

fn attestation_tag(outcome: &CustodyAttestationOutcome) -> String {
    use CustodyAttestationOutcome as O;
    let name = match outcome {
        O::FixtureAttestationAccepted { .. } => "accept:FixtureAttestationAccepted",
        O::AttestationDisabled => "reject:AttestationDisabled",
        O::FixtureRejectedProductionRequired => "reject:FixtureRejectedProductionRequired",
        O::FixtureRejectedMainnetProductionRequired => {
            "reject:FixtureRejectedMainnetProductionRequired"
        }
        O::RemoteSignerAttestationUnavailable => "reject:RemoteSignerAttestationUnavailable",
        O::KmsAttestationUnavailable => "reject:KmsAttestationUnavailable",
        O::HsmAttestationUnavailable => "reject:HsmAttestationUnavailable",
        O::CloudKmsAttestationUnavailable => "reject:CloudKmsAttestationUnavailable",
        O::Pkcs11HsmAttestationUnavailable => "reject:Pkcs11HsmAttestationUnavailable",
        O::ProductionAttestationUnavailable => "reject:ProductionAttestationUnavailable",
        O::MainNetProductionAttestationUnavailable => {
            "reject:MainNetProductionAttestationUnavailable"
        }
        O::FixtureRejectedForMainNet => "reject:FixtureRejectedForMainNet",
        O::AttestationClassPolicyMismatch { .. } => "reject:AttestationClassPolicyMismatch",
        O::UnknownAttestationClassRejected { .. } => "reject:UnknownAttestationClassRejected",
        O::WrongEnvironment { .. } => "reject:WrongEnvironment",
        O::WrongChain { .. } => "reject:WrongChain",
        O::WrongGenesis { .. } => "reject:WrongGenesis",
        O::WrongAuthorityRoot { .. } => "reject:WrongAuthorityRoot",
        O::WrongSigningKeyFingerprint { .. } => "reject:WrongSigningKeyFingerprint",
        O::WrongCustodyClass { .. } => "reject:WrongCustodyClass",
        O::WrongBackendProviderSignerId { .. } => "reject:WrongBackendProviderSignerId",
        O::WrongKeyId { .. } => "reject:WrongKeyId",
        O::WrongSuite { .. } => "reject:WrongSuite",
        O::WrongLifecycleAction { .. } => "reject:WrongLifecycleAction",
        O::WrongCandidateDigest { .. } => "reject:WrongCandidateDigest",
        O::WrongAuthorityDomainSequence { .. } => "reject:WrongAuthorityDomainSequence",
        O::WrongGovernanceProofDigest { .. } => "reject:WrongGovernanceProofDigest",
        O::WrongRequestDigest { .. } => "reject:WrongRequestDigest",
        O::WrongResponseDigest { .. } => "reject:WrongResponseDigest",
        O::WrongTranscriptDigest { .. } => "reject:WrongTranscriptDigest",
        O::StaleOrReplayedAttestation => "reject:StaleOrReplayedAttestation",
        O::ExpiredAttestation { .. } => "reject:ExpiredAttestation",
        O::MalformedAttestationEvidence { .. } => "reject:MalformedAttestationEvidence",
        O::UnsupportedAttestationVersion { .. } => "reject:UnsupportedAttestationVersion",
        O::InvalidAttestationCommitment => "reject:InvalidAttestationCommitment",
        O::LocalOperatorCannotSatisfyProductionAttestation => {
            "reject:LocalOperatorCannotSatisfyProductionAttestation"
        }
        O::PeerMajorityCannotSatisfyProductionAttestation => {
            "reject:PeerMajorityCannotSatisfyProductionAttestation"
        }
    };
    name.to_string()
}

fn composition_tag(outcome: &CustodyMetadataAttestationOutcome) -> String {
    use CustodyMetadataAttestationOutcome as O;
    match outcome {
        O::Accepted { .. } => "accept:Accepted",
        O::LifecycleOrCustodyRejected(_) => "reject:LifecycleOrCustodyRejected",
        O::AttestationRejected { .. } => "reject:AttestationRejected",
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

    // A1 — fixture attestation accepted under explicit fixture policy on DevNet.
    let a1 = accepted_scenario(Env::Devnet);
    t.check(
        "A1",
        "accept:FixtureAttestationAccepted",
        &attestation_tag(&verify(&a1, CustodyAttestationPolicy::FixtureAttestationAllowed)),
    );

    // A2 — fixture attestation accepted under explicit fixture policy on TestNet.
    let a2 = accepted_scenario(Env::Testnet);
    t.check(
        "A2",
        "accept:FixtureAttestationAccepted",
        &attestation_tag(&verify(&a2, CustodyAttestationPolicy::FixtureAttestationAllowed)),
    );

    let s = accepted_scenario(Env::Devnet);

    // A3 — attestation evidence digest deterministic + domain-bound.
    let mut other_ev = s.evidence.clone();
    other_ev.candidate_digest = "different".to_string();
    t.assert_true(
        "A3",
        s.evidence.evidence_digest() == s.evidence.evidence_digest()
            && s.evidence.evidence_digest() != other_ev.evidence_digest(),
        "evidence digest stable + changes when a bound field changes",
    );

    // A4 — attestation input digest deterministic + domain-bound.
    let mut other_in = s.input.clone();
    other_in.expected_authority_domain_sequence = 3;
    t.assert_true(
        "A4",
        s.input.input_digest() == s.input.input_digest()
            && s.input.input_digest() != other_in.input_digest(),
        "input digest stable + changes when a bound field changes",
    );

    // A5 — attestation transcript digest deterministic + order-sensitive.
    let ev = s.evidence.evidence_digest();
    let inp = s.input.input_digest();
    let trans = attestation_transcript_digest(&ev, &inp);
    t.assert_true(
        "A5",
        trans == attestation_transcript_digest(&ev, &inp)
            && trans != attestation_transcript_digest(&inp, &ev),
        "transcript digest stable, bound, and order-sensitive in its inputs",
    );

    // A6 — provider identity digest deterministic + domain-bound.
    let mut other_prov = s.evidence.clone();
    other_prov.backend_provider_signer_id = "different-provider".to_string();
    t.assert_true(
        "A6",
        s.evidence.provider_identity_digest() == s.evidence.provider_identity_digest()
            && s.evidence.provider_identity_digest() != other_prov.provider_identity_digest(),
        "provider identity digest stable + changes when the provider id changes",
    );

    // A7 — evidence binds environment, chain, genesis, authority root,
    //      signing-key fingerprint, custody class, backend/signer id, key id,
    //      lifecycle action, candidate digest, and authority-domain sequence.
    let e = &s.evidence;
    t.assert_true(
        "A7",
        e.environment == Env::Devnet
            && e.chain_id == CHAIN_ID
            && e.genesis_hash == GENESIS_HASH
            && e.authority_root_fingerprint == ROOT_FP
            && e.bundle_signing_key_fingerprint == s.candidate.active_bundle_signing_key_fingerprint
            && e.custody_class == AuthorityCustodyClass::Kms
            && e.backend_provider_signer_id == PROVIDER_ID
            && e.custody_key_id == KEY_ID
            && e.lifecycle_action == LocalLifecycleAction::Rotate
            && e.candidate_digest == DIGEST_2
            && e.authority_domain_sequence == 2
            && e.is_well_formed(),
        "evidence binds env/chain/genesis/root/signing-key/custody/backend/key/action/candidate/sequence",
    );

    // A8 — fixture attestation composes with Run 188 custody metadata.
    {
        let custody = good_custody_attestation(Env::Devnet, &s.candidate);
        let prior = prior_versioned(Env::Devnet);
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
        t.check("A8", "accept:Accepted", &composition_tag(&outcome));
    }

    // A9 — fixture attestation composes with Run 203 fixture KMS backend
    //      evidence (Kms custody class + FixtureKms backend kind tag bound).
    {
        let mut s9 = accepted_scenario(Env::Devnet);
        s9.evidence.custody_class = AuthorityCustodyClass::Kms;
        s9.evidence.custody_backend_kind = Some(BackendKind::FixtureKms.tag().to_string());
        s9.input.expected_custody_class = AuthorityCustodyClass::Kms;
        t.check(
            "A9",
            "accept:FixtureAttestationAccepted",
            &attestation_tag(&verify(&s9, CustodyAttestationPolicy::FixtureAttestationAllowed)),
        );
    }

    // A10 — fixture attestation composes with Run 203 fixture HSM backend
    //       evidence (Hsm custody class + FixtureHsm backend kind tag bound).
    {
        let mut s10 = accepted_scenario(Env::Testnet);
        s10.evidence.custody_class = AuthorityCustodyClass::Hsm;
        s10.evidence.custody_backend_kind = Some(BackendKind::FixtureHsm.tag().to_string());
        s10.input.expected_custody_class = AuthorityCustodyClass::Hsm;
        t.check(
            "A10",
            "accept:FixtureAttestationAccepted",
            &attestation_tag(&verify(&s10, CustodyAttestationPolicy::FixtureAttestationAllowed)),
        );
    }

    // A11 — fixture attestation composes with Run 201 fixture RemoteSigner
    //       transport evidence (request/response/transcript bound as opaque
    //       evidence fields; the RemoteSigner path stays separate).
    {
        let rs_transcript =
            backend_transcript_digest("rs-identity-digest", "rs-request-digest", "rs-response-digest");
        let mut s11 = accepted_scenario(Env::Devnet);
        s11.evidence.custody_backend_kind = Some("remote-signer-transport".to_string());
        s11.evidence.request_digest = Some("rs-request-digest".to_string());
        s11.evidence.response_digest = Some("rs-response-digest".to_string());
        s11.evidence.transcript_digest = Some(rs_transcript.clone());
        s11.input.expected_request_digest = Some("rs-request-digest".to_string());
        s11.input.expected_response_digest = Some("rs-response-digest".to_string());
        s11.input.expected_transcript_digest = Some(rs_transcript);
        t.check(
            "A11",
            "accept:FixtureAttestationAccepted",
            &attestation_tag(&verify(&s11, CustodyAttestationPolicy::FixtureAttestationAllowed)),
        );
    }

    // A12 — production attestation boundary callable, returns typed unavailable.
    {
        let s12 = accepted_scenario(Env::Devnet);
        let verifier = ProductionAttestationVerifier;
        let outcome = verifier.verify_custody_attestation(
            &s12.evidence,
            &s12.input,
            &s12.domain,
            CustodyAttestationPolicy::ProductionAttestationRequired,
        );
        t.assert_true(
            "A12",
            verifier.class() == CustodyAttestationClass::ProductionAttestationUnavailable
                && outcome == CustodyAttestationOutcome::ProductionAttestationUnavailable
                && outcome.is_unavailable(),
            "production attestation verifier callable, fails closed unavailable",
        );
    }

    // A13 — cloud KMS attestation boundary callable, returns typed unavailable.
    {
        let s13 = accepted_scenario(Env::Devnet);
        let verifier = CloudKmsAttestationVerifier;
        let outcome = verifier.verify_custody_attestation(
            &s13.evidence,
            &s13.input,
            &s13.domain,
            CustodyAttestationPolicy::KmsAttestationRequired,
        );
        t.assert_true(
            "A13",
            verifier.class() == CustodyAttestationClass::CloudKmsAttestationUnavailable
                && outcome == CustodyAttestationOutcome::CloudKmsAttestationUnavailable
                && outcome.is_unavailable(),
            "cloud KMS attestation verifier callable, fails closed unavailable",
        );
    }

    // A14 — PKCS#11 HSM attestation boundary callable, returns typed
    //       unavailable.
    {
        let s14 = accepted_scenario(Env::Devnet);
        let verifier = Pkcs11HsmAttestationVerifier;
        let outcome = verifier.verify_custody_attestation(
            &s14.evidence,
            &s14.input,
            &s14.domain,
            CustodyAttestationPolicy::HsmAttestationRequired,
        );
        t.assert_true(
            "A14",
            verifier.class() == CustodyAttestationClass::Pkcs11HsmAttestationUnavailable
                && outcome == CustodyAttestationOutcome::Pkcs11HsmAttestationUnavailable
                && outcome.is_unavailable(),
            "PKCS#11 HSM attestation verifier callable, fails closed unavailable",
        );
    }

    // A15 — GenesisBound / EmergencyCouncil / OnChainGovernance proof
    //       behavior unchanged when attestation policy is Disabled (the
    //       attestation layer rejects inertly as AttestationDisabled).
    {
        let mut a15_ok = true;
        for gov in [
            GovernanceAuthorityClass::GenesisBound,
            GovernanceAuthorityClass::EmergencyCouncil,
            GovernanceAuthorityClass::OnChainGovernance,
        ] {
            let candidate = rotate_candidate(Env::Devnet);
            let custody = AuthorityCustodyAttestation {
                governance_authority_class: gov,
                ..good_custody_attestation(Env::Devnet, &candidate)
            };
            let sc = accepted_scenario(Env::Devnet);
            let prior = prior_versioned(Env::Devnet);
            let outcome = validate_custody_metadata_and_attestation(
                &custody,
                &candidate,
                Some(&prior),
                &sc.domain,
                gov,
                LocalLifecycleAction::Rotate,
                DIGEST_2,
                2,
                Some(KEY_ID),
                AuthorityCustodyPolicy::FixtureOnly,
                &sc.evidence,
                &sc.input,
                CustodyAttestationPolicy::Disabled,
                NOW,
                false,
            );
            a15_ok &= matches!(
                outcome,
                CustodyMetadataAttestationOutcome::AttestationRejected {
                    attestation_outcome: CustodyAttestationOutcome::AttestationDisabled,
                    ..
                }
            );
        }
        t.assert_true(
            "A15",
            a15_ok,
            "Disabled attestation policy does not disturb governance proof behavior",
        );
    }

    t.finish(out)
}

// ---------------------------------------------------------------------------
// Table 2 — rejection cases R1..R40.
// ---------------------------------------------------------------------------

fn run_rejection_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("rejection");
    let dev = || accepted_scenario(Env::Devnet);

    // R1 — attestation rejected under Disabled policy.
    t.check(
        "R1",
        "reject:AttestationDisabled",
        &attestation_tag(&verify(&dev(), CustodyAttestationPolicy::Disabled)),
    );

    // R2 — fixture attestation rejected under ProductionAttestationRequired.
    t.check(
        "R2",
        "reject:FixtureRejectedProductionRequired",
        &attestation_tag(&verify(&dev(), CustodyAttestationPolicy::ProductionAttestationRequired)),
    );

    // R3 — fixture attestation rejected under MainnetProductionAttestationRequired.
    t.check(
        "R3",
        "reject:FixtureRejectedMainnetProductionRequired",
        &attestation_tag(&verify(
            &dev(),
            CustodyAttestationPolicy::MainnetProductionAttestationRequired,
        )),
    );

    // R4 — RemoteSigner attestation rejected as unavailable.
    {
        let mut s = dev();
        s.evidence.attestation_class = CustodyAttestationClass::RemoteSignerAttestation;
        t.assert_true(
            "R4",
            verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed)
                == CustodyAttestationOutcome::RemoteSignerAttestationUnavailable
                && verify(&s, CustodyAttestationPolicy::RemoteSignerAttestationRequired)
                    == CustodyAttestationOutcome::RemoteSignerAttestationUnavailable,
            "RemoteSigner attestation refused as unavailable under both policies",
        );
    }

    // R5 — KMS attestation rejected as unavailable.
    {
        let mut s = dev();
        s.evidence.attestation_class = CustodyAttestationClass::KmsAttestation;
        t.assert_true(
            "R5",
            verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed)
                == CustodyAttestationOutcome::KmsAttestationUnavailable
                && verify(&s, CustodyAttestationPolicy::KmsAttestationRequired)
                    == CustodyAttestationOutcome::KmsAttestationUnavailable,
            "KMS attestation refused as unavailable under both policies",
        );
    }

    // R6 — HSM attestation rejected as unavailable.
    {
        let mut s = dev();
        s.evidence.attestation_class = CustodyAttestationClass::HsmAttestation;
        t.assert_true(
            "R6",
            verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed)
                == CustodyAttestationOutcome::HsmAttestationUnavailable
                && verify(&s, CustodyAttestationPolicy::HsmAttestationRequired)
                    == CustodyAttestationOutcome::HsmAttestationUnavailable,
            "HSM attestation refused as unavailable under both policies",
        );
    }

    // R7 — cloud KMS attestation rejected as unavailable.
    {
        let mut s = dev();
        s.evidence.attestation_class = CustodyAttestationClass::CloudKmsAttestationUnavailable;
        t.check(
            "R7",
            "reject:CloudKmsAttestationUnavailable",
            &attestation_tag(&verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed)),
        );
    }

    // R8 — PKCS#11 HSM attestation rejected as unavailable.
    {
        let mut s = dev();
        s.evidence.attestation_class = CustodyAttestationClass::Pkcs11HsmAttestationUnavailable;
        t.check(
            "R8",
            "reject:Pkcs11HsmAttestationUnavailable",
            &attestation_tag(&verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed)),
        );
    }

    // R9 — production attestation rejected as unavailable.
    {
        let mut s = dev();
        s.evidence.attestation_class = CustodyAttestationClass::ProductionAttestationUnavailable;
        t.assert_true(
            "R9",
            verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed)
                == CustodyAttestationOutcome::ProductionAttestationUnavailable
                && verify(&s, CustodyAttestationPolicy::ProductionAttestationRequired)
                    == CustodyAttestationOutcome::ProductionAttestationUnavailable,
            "production attestation refused as unavailable under both policies",
        );
    }

    // R10 — MainNet production attestation rejected as unavailable.
    {
        let mut s = dev();
        s.evidence.attestation_class = CustodyAttestationClass::ProductionAttestationUnavailable;
        t.check(
            "R10",
            "reject:MainNetProductionAttestationUnavailable",
            &attestation_tag(&verify(
                &s,
                CustodyAttestationPolicy::MainnetProductionAttestationRequired,
            )),
        );
    }

    // R11 — unknown attestation class rejected.
    {
        let mut s = dev();
        s.evidence.attestation_class = CustodyAttestationClass::Unknown;
        t.check(
            "R11",
            "reject:UnknownAttestationClassRejected",
            &attestation_tag(&verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed)),
        );
    }

    // R12 — wrong environment rejected.
    {
        let mut s = dev();
        s.evidence.environment = Env::Testnet;
        t.check(
            "R12",
            "reject:WrongEnvironment",
            &attestation_tag(&verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed)),
        );
    }

    // R13 — wrong chain rejected.
    {
        let mut s = dev();
        s.evidence.chain_id = "9999999999999999".to_string();
        t.check(
            "R13",
            "reject:WrongChain",
            &attestation_tag(&verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed)),
        );
    }

    // R14 — wrong genesis rejected.
    {
        let mut s = dev();
        s.evidence.genesis_hash = "ffff".to_string();
        t.check(
            "R14",
            "reject:WrongGenesis",
            &attestation_tag(&verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed)),
        );
    }

    // R15 — wrong authority root rejected.
    {
        let mut s = dev();
        s.evidence.authority_root_fingerprint = "ffff".to_string();
        t.check(
            "R15",
            "reject:WrongAuthorityRoot",
            &attestation_tag(&verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed)),
        );
    }

    // R16 — wrong signing-key fingerprint rejected.
    {
        let mut s = dev();
        s.evidence.bundle_signing_key_fingerprint = "ffff".to_string();
        t.check(
            "R16",
            "reject:WrongSigningKeyFingerprint",
            &attestation_tag(&verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed)),
        );
    }

    // R17 — wrong custody class rejected.
    {
        let mut s = dev();
        s.evidence.custody_class = AuthorityCustodyClass::Hsm;
        t.check(
            "R17",
            "reject:WrongCustodyClass",
            &attestation_tag(&verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed)),
        );
    }

    // R18 — wrong backend/provider/signer id rejected.
    {
        let mut s = dev();
        s.evidence.backend_provider_signer_id = "other".to_string();
        t.check(
            "R18",
            "reject:WrongBackendProviderSignerId",
            &attestation_tag(&verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed)),
        );
    }

    // R19 — wrong key id / key label rejected.
    {
        let mut s = dev();
        s.evidence.custody_key_id = "other".to_string();
        t.check(
            "R19",
            "reject:WrongKeyId",
            &attestation_tag(&verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed)),
        );
    }

    // R20 — wrong suite rejected.
    {
        let mut s = dev();
        s.evidence.suite_id = 200;
        t.check(
            "R20",
            "reject:WrongSuite",
            &attestation_tag(&verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed)),
        );
    }

    // R21 — wrong lifecycle action rejected.
    {
        let mut s = dev();
        s.evidence.lifecycle_action = LocalLifecycleAction::Revoke;
        t.check(
            "R21",
            "reject:WrongLifecycleAction",
            &attestation_tag(&verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed)),
        );
    }

    // R22 — wrong candidate digest rejected.
    {
        let mut s = dev();
        s.evidence.candidate_digest = "ffff".to_string();
        t.check(
            "R22",
            "reject:WrongCandidateDigest",
            &attestation_tag(&verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed)),
        );
    }

    // R23 — wrong authority-domain sequence rejected.
    {
        let mut s = dev();
        s.evidence.authority_domain_sequence = 7;
        t.check(
            "R23",
            "reject:WrongAuthorityDomainSequence",
            &attestation_tag(&verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed)),
        );
    }

    // R24 — wrong governance proof digest rejected.
    {
        let mut s = dev();
        s.evidence.governance_proof_digest = Some("other".to_string());
        t.check(
            "R24",
            "reject:WrongGovernanceProofDigest",
            &attestation_tag(&verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed)),
        );
    }

    // R25 — wrong request digest rejected.
    {
        let mut s = dev();
        s.evidence.request_digest = Some("other".to_string());
        t.check(
            "R25",
            "reject:WrongRequestDigest",
            &attestation_tag(&verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed)),
        );
    }

    // R26 — wrong response digest rejected.
    {
        let mut s = dev();
        s.evidence.response_digest = Some("other".to_string());
        t.check(
            "R26",
            "reject:WrongResponseDigest",
            &attestation_tag(&verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed)),
        );
    }

    // R27 — wrong transcript digest rejected.
    {
        let mut s = dev();
        s.evidence.transcript_digest = Some("other".to_string());
        t.check(
            "R27",
            "reject:WrongTranscriptDigest",
            &attestation_tag(&verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed)),
        );
    }

    // R28 — stale/replayed attestation rejected (nonce mismatch + issuance
    //       timestamp outside the replay window).
    {
        let mut s = dev();
        s.evidence.attestation_nonce = "stale".to_string();
        let nonce_reject = verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed)
            == CustodyAttestationOutcome::StaleOrReplayedAttestation;
        let mut s2 = dev();
        s2.evidence.issued_at_unix = Some(WINDOW_UNTIL + 10);
        let window_reject = verify(&s2, CustodyAttestationPolicy::FixtureAttestationAllowed)
            == CustodyAttestationOutcome::StaleOrReplayedAttestation;
        t.assert_true(
            "R28",
            nonce_reject && window_reject,
            "stale nonce and out-of-window issuance both refused as StaleOrReplayedAttestation",
        );
    }

    // R29 — expired attestation rejected.
    {
        let mut s = dev();
        s.input.now_unix = EXPIRES + 1;
        t.check(
            "R29",
            "reject:ExpiredAttestation",
            &attestation_tag(&verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed)),
        );
    }

    // R30 — malformed attestation evidence rejected.
    {
        let mut s = dev();
        s.evidence.attestation_nonce = String::new();
        t.check(
            "R30",
            "reject:MalformedAttestationEvidence",
            &attestation_tag(&verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed)),
        );
    }

    // R31 — unsupported attestation version rejected.
    {
        let mut s = dev();
        s.evidence.attestation_version = 99;
        t.check(
            "R31",
            "reject:UnsupportedAttestationVersion",
            &attestation_tag(&verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed)),
        );
    }

    // R32 — invalid attestation commitment rejected.
    {
        let mut s = dev();
        s.evidence.attestation_commitment =
            CUSTODY_ATTESTATION_INVALID_COMMITMENT_SENTINEL.to_string();
        t.check(
            "R32",
            "reject:InvalidAttestationCommitment",
            &attestation_tag(&verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed)),
        );
    }

    // R33 — local operator cannot satisfy production attestation.
    t.assert_true(
        "R33",
        local_operator_cannot_satisfy_production_attestation(),
        "a local operator key cannot satisfy a production custody attestation policy",
    );

    // R34 — peer majority cannot satisfy production attestation.
    t.assert_true(
        "R34",
        peer_majority_cannot_satisfy_production_attestation(),
        "peer majority cannot satisfy a production custody attestation policy",
    );

    // R35 — attestation valid but custody metadata invalid rejected (rejects
    //       at the Run 188 custody layer).
    {
        let s = dev();
        let mut custody = good_custody_attestation(Env::Devnet, &s.candidate);
        custody.custody_key_id = "wrong-key".to_string();
        let prior = prior_versioned(Env::Devnet);
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
        t.check(
            "R35",
            "reject:LifecycleOrCustodyRejected",
            &composition_tag(&outcome),
        );
    }

    // R36 — custody valid but attestation invalid rejected (rejects at the
    //       attestation layer).
    {
        let mut s = dev();
        s.evidence.candidate_digest = "wrong".to_string();
        let custody = good_custody_attestation(Env::Devnet, &s.candidate);
        let prior = prior_versioned(Env::Devnet);
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
        t.assert_true(
            "R36",
            matches!(
                outcome,
                CustodyMetadataAttestationOutcome::AttestationRejected {
                    attestation_outcome: CustodyAttestationOutcome::WrongCandidateDigest { .. },
                    ..
                }
            ),
            "custody valid but invalid attestation rejects at the attestation layer",
        );
    }

    // R37 — lifecycle + governance + custody valid but production attestation
    //       unavailable rejected.
    {
        let s = dev();
        let custody = good_custody_attestation(Env::Devnet, &s.candidate);
        let prior = prior_versioned(Env::Devnet);
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
        t.assert_true(
            "R37",
            matches!(
                outcome,
                CustodyMetadataAttestationOutcome::AttestationRejected {
                    attestation_outcome:
                        CustodyAttestationOutcome::FixtureRejectedProductionRequired,
                    ..
                }
            ),
            "lifecycle+governance+custody valid but production attestation unavailable",
        );
    }

    // R38 — validation-only rejection remains non-mutating.
    {
        let s = dev();
        let before_ev = s.evidence.clone();
        let before_in = s.input.clone();
        let o1 = verify(&s, CustodyAttestationPolicy::Disabled);
        let o2 = verify(&s, CustodyAttestationPolicy::ProductionAttestationRequired);
        let o3 = verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed);
        t.assert_true(
            "R38",
            o1.is_reject()
                && o2.is_reject()
                && o3.is_accept()
                && s.evidence == before_ev
                && s.input == before_in,
            "repeated validation leaves evidence + input byte-identical",
        );
    }

    // R39 — mutating preflight rejection produces no Run 070 call, no live
    //       trust swap, no session eviction, no sequence write, no marker
    //       write (the composition is pure and returns a typed reject).
    {
        let mut s = dev();
        s.evidence.attestation_commitment =
            CUSTODY_ATTESTATION_INVALID_COMMITMENT_SENTINEL.to_string();
        let custody = good_custody_attestation(Env::Devnet, &s.candidate);
        let prior = prior_versioned(Env::Devnet);
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
        t.assert_true(
            "R39",
            outcome.is_reject() && s.candidate == candidate_before,
            "mutating-preflight rejection returns a typed reject without mutating the candidate",
        );
    }

    // R40 — MainNet peer-driven apply remains refused even with fixture
    //       attestation.
    {
        let env = Env::Mainnet;
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
        let verifier_refused = verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed)
            == CustodyAttestationOutcome::FixtureRejectedForMainNet;
        t.assert_true(
            "R40",
            outcome == CustodyMetadataAttestationOutcome::MainNetPeerDrivenApplyRefused
                && verifier_refused
                && mainnet_peer_driven_apply_remains_refused_under_attestation_boundary(env),
            "MainNet peer-driven apply refused even with valid fixture attestation material",
        );
    }

    t.finish(out)
}

// ---------------------------------------------------------------------------
// Table 3 — separation / fail-closed / class-policy extras.
// ---------------------------------------------------------------------------

fn run_separation_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("separation");

    // Fixture attestation refused for MainNet (DevNet/TestNet evidence-only).
    {
        let env = Env::Mainnet;
        let candidate = rotate_candidate(env);
        let s = Scenario {
            domain: domain(env),
            candidate: candidate.clone(),
            evidence: evidence(CustodyAttestationClass::FixtureAttestation, env, &candidate),
            input: input(env, &candidate),
        };
        t.check(
            "fixture-rejected-mainnet",
            "reject:FixtureRejectedForMainNet",
            &attestation_tag(&verify(&s, CustodyAttestationPolicy::FixtureAttestationAllowed)),
        );
    }

    // Production / cloud-KMS / PKCS#11 / HSM / RemoteSigner attestation
    // verifiers perform no I/O and fail closed on both DevNet and TestNet.
    {
        let mut prod_ok = true;
        for env in [Env::Devnet, Env::Testnet] {
            let s = accepted_scenario(env);
            prod_ok &= RemoteSignerAttestationVerifier.verify_custody_attestation(
                &s.evidence,
                &s.input,
                &s.domain,
                CustodyAttestationPolicy::RemoteSignerAttestationRequired,
            ) == CustodyAttestationOutcome::RemoteSignerAttestationUnavailable;
            prod_ok &= KmsAttestationVerifier.verify_custody_attestation(
                &s.evidence,
                &s.input,
                &s.domain,
                CustodyAttestationPolicy::KmsAttestationRequired,
            ) == CustodyAttestationOutcome::KmsAttestationUnavailable;
            prod_ok &= HsmAttestationVerifier.verify_custody_attestation(
                &s.evidence,
                &s.input,
                &s.domain,
                CustodyAttestationPolicy::HsmAttestationRequired,
            ) == CustodyAttestationOutcome::HsmAttestationUnavailable;
            prod_ok &= CloudKmsAttestationVerifier.verify_custody_attestation(
                &s.evidence,
                &s.input,
                &s.domain,
                CustodyAttestationPolicy::KmsAttestationRequired,
            ) == CustodyAttestationOutcome::CloudKmsAttestationUnavailable;
            prod_ok &= Pkcs11HsmAttestationVerifier.verify_custody_attestation(
                &s.evidence,
                &s.input,
                &s.domain,
                CustodyAttestationPolicy::HsmAttestationRequired,
            ) == CustodyAttestationOutcome::Pkcs11HsmAttestationUnavailable;
            prod_ok &= ProductionAttestationVerifier.verify_custody_attestation(
                &s.evidence,
                &s.input,
                &s.domain,
                CustodyAttestationPolicy::ProductionAttestationRequired,
            ) == CustodyAttestationOutcome::ProductionAttestationUnavailable;
        }
        t.assert_true(
            "production-no-io-fail-closed",
            prod_ok,
            "production/cloud-KMS/PKCS#11/HSM/RemoteSigner attestation verifiers fail closed, no I/O",
        );
    }

    // Fixture attestation verifier is mockable as a trait object.
    {
        let s = accepted_scenario(Env::Devnet);
        let verifier = FixtureCustodyAttestationVerifier;
        let dynref: &dyn CustodyAttestationVerifier = &verifier;
        t.assert_true(
            "trait-object-mockable",
            dynref.class() == CustodyAttestationClass::FixtureAttestation
                && dynref
                    .verify_custody_attestation(
                        &s.evidence,
                        &s.input,
                        &s.domain,
                        CustodyAttestationPolicy::FixtureAttestationAllowed,
                    )
                    .is_accept(),
            "CustodyAttestationVerifier is usable as a trait object",
        );
    }

    // Default policy is Disabled and fails closed even with valid fixture
    // evidence.
    {
        let s = accepted_scenario(Env::Devnet);
        t.check(
            "default-policy-disabled",
            "reject:AttestationDisabled",
            &attestation_tag(&verify(&s, CustodyAttestationPolicy::default())),
        );
    }

    // Production-required policy still refuses a production-class attestation
    // as unavailable (no real verifier), proving the production attestation
    // surface is callable but fail-closed regardless of policy.
    {
        let mut s = accepted_scenario(Env::Devnet);
        s.evidence.attestation_class = CustodyAttestationClass::KmsAttestation;
        t.check(
            "production-class-required-unavailable",
            "reject:KmsAttestationUnavailable",
            &attestation_tag(&verify(&s, CustodyAttestationPolicy::KmsAttestationRequired)),
        );
    }

    t.finish(out)
}

// ---------------------------------------------------------------------------
// Table 4 — full custody-metadata + attestation composition.
// ---------------------------------------------------------------------------

fn run_composition_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("composition");

    // Accepted: Run 188 custody metadata + Run 205 fixture attestation.
    {
        let s = accepted_scenario(Env::Devnet);
        let custody = good_custody_attestation(Env::Devnet, &s.candidate);
        let prior = prior_versioned(Env::Devnet);
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
        t.check("compose-accepted", "accept:Accepted", &composition_tag(&outcome));
    }

    // Custody rejected at the Run 188 layer (attestation not consulted).
    {
        let s = accepted_scenario(Env::Devnet);
        let mut custody = good_custody_attestation(Env::Devnet, &s.candidate);
        custody.custody_class = AuthorityCustodyClass::Kms; // not accepted by FixtureOnly
        let prior = prior_versioned(Env::Devnet);
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
        t.check(
            "compose-custody-rejected",
            "reject:LifecycleOrCustodyRejected",
            &composition_tag(&outcome),
        );
    }

    // Custody accepted but attestation rejected (production required).
    {
        let s = accepted_scenario(Env::Devnet);
        let custody = good_custody_attestation(Env::Devnet, &s.candidate);
        let prior = prior_versioned(Env::Devnet);
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
        t.check(
            "compose-attestation-rejected",
            "reject:AttestationRejected",
            &composition_tag(&outcome),
        );
    }

    // MainNet peer-driven apply refused even with fixture attestation.
    {
        let env = Env::Mainnet;
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
        let a = accepted_scenario(env);
        let b = accepted_scenario(env);
        let outcome_a =
            attestation_tag(&verify(&a, CustodyAttestationPolicy::FixtureAttestationAllowed));
        let outcome_b =
            attestation_tag(&verify(&b, CustodyAttestationPolicy::FixtureAttestationAllowed));
        let ev_eq = a.evidence.evidence_digest() == b.evidence.evidence_digest();
        let in_eq = a.input.input_digest() == b.input.input_digest();
        let prov_eq = a.evidence.provider_identity_digest() == b.evidence.provider_identity_digest();
        let trans_eq = attestation_transcript_digest(
            &a.evidence.evidence_digest(),
            &a.input.input_digest(),
        ) == attestation_transcript_digest(
            &b.evidence.evidence_digest(),
            &b.input.input_digest(),
        );
        t.assert_true(
            &format!("determinism-{label}"),
            outcome_a == outcome_b && ev_eq && in_eq && prov_eq && trans_eq,
            "repeat scenario produces identical outcome + evidence/input/provider/transcript digests",
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
        mainnet_peer_driven_apply_remains_refused_under_attestation_boundary(Env::Mainnet)
            && !mainnet_peer_driven_apply_remains_refused_under_attestation_boundary(Env::Devnet)
            && !mainnet_peer_driven_apply_remains_refused_under_attestation_boundary(Env::Testnet),
        "MainNet refused; DevNet/TestNet not flagged by the refusal helper",
    );
    t.assert_true(
        "local-operator-refusal-helper",
        local_operator_cannot_satisfy_production_attestation(),
        "a local operator key cannot satisfy a production custody attestation policy",
    );
    t.assert_true(
        "peer-majority-refusal-helper",
        peer_majority_cannot_satisfy_production_attestation(),
        "peer majority cannot satisfy a production custody attestation policy",
    );

    t.finish(out)
}

// ---------------------------------------------------------------------------
// Fixture dump — evidence/input/transcript for the evidence archive.
// ---------------------------------------------------------------------------

fn run_fixture_dump(out: &Path) {
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);
    write_file(
        &out.join("fixtures").join("evidence.txt"),
        &format!("{:#?}\nevidence_digest={}\n", s.evidence, s.evidence.evidence_digest()),
    );
    write_file(
        &out.join("fixtures").join("input.txt"),
        &format!("{:#?}\ninput_digest={}\n", s.input, s.input.input_digest()),
    );
    write_file(
        &out.join("fixtures").join("provider_identity.txt"),
        &format!("provider_identity_digest={}\n", s.evidence.provider_identity_digest()),
    );
    write_file(
        &out.join("fixtures").join("transcript_digest.txt"),
        &format!(
            "evidence_digest={}\ninput_digest={}\ntranscript_digest={}\n",
            s.evidence.evidence_digest(),
            s.input.input_digest(),
            attestation_transcript_digest(
                &s.evidence.evidence_digest(),
                &s.input.input_digest()
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
            eprintln!("usage: run_206_custody_attestation_release_binary_helper <OUT_DIR>");
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
    summary.push_str("run_206_custody_attestation_release_binary_helper\n");
    summary.push_str(
        "scope: Run 205 production custody attestation verifier boundary over the Run 188 custody boundary (release binary)\n",
    );
    summary.push_str(
        "note: fixture-only; no real cloud-KMS/PKCS#11/HSM-vendor/RemoteSigner attestation verifier; no real KMS/HSM/RemoteSigner backend; no live trust mutation; no P2P socket; production attestation verifiers fail-closed; MainNet peer-driven apply remains refused\n\n",
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
