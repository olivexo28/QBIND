//! Run 208 — release-built helper that exercises the Run 207
//! **custody-attestation payload carrying and production-context routing**
//! surface
//! ([`qbind_node::pqc_custody_attestation_payload_carrying`]) **in release
//! mode**, through the production library symbols, layered over the Run 205
//! production custody-attestation verifier boundary
//! ([`qbind_node::pqc_custody_attestation_verifier`]) and the Run 188
//! authority-custody boundary
//! ([`qbind_node::pqc_authority_custody`]).
//!
//! Per `task/RUN_208_TASK.txt`, Run 208 is the release-binary evidence run
//! for the Run 207 source/test custody-attestation payload/carrying and
//! production-context wiring. This helper is fixture-only tooling and:
//!
//! * does NOT modify any production runtime code, CLI flag, env var, or
//!   wire / marker / sequence / trust-bundle / peer-candidate-envelope
//!   schema beyond the Run 207 additive optional `custody_attestation`
//!   sibling already established by Runs 070, 130–207;
//! * does NOT enable MainNet peer-driven apply on any surface;
//! * does NOT mutate any live trust state, write any marker, advance any
//!   sequence, swap any live trust, evict any session, or invoke Run 070 —
//!   every parser, loader, routing helper, and composition function
//!   exercised here is a pure function returning an owned typed outcome;
//! * does NOT open any P2P socket and performs no network or backend I/O;
//! * does NOT implement any real cloud-KMS attestation verifier, real
//!   PKCS#11 attestation verifier, real HSM-vendor attestation verifier,
//!   real RemoteSigner attestation verifier, real KMS/HSM backend, or real
//!   RemoteSigner backend; carried production / cloud-KMS / PKCS#11 / HSM /
//!   RemoteSigner attestation material always routes into the Run 205
//!   verifier and returns the typed unavailable reject;
//! * never elevates the DevNet/TestNet fixture custody attestation into
//!   MainNet production custody (MainNet peer-driven apply always refuses at
//!   the typed boundary);
//! * exists alongside (and does NOT replace) the Run 207 source/test target
//!   `crates/qbind-node/tests/run_207_custody_attestation_payload_callsite_tests.rs`.
//!
//! The helper proves, in release mode through the production library
//! symbols:
//!
//! 1. legacy/no-attestation payloads remain compatible under default
//!    `Disabled` behavior;
//! 2. fixture custody attestation reaches production-context paths in
//!    release mode where policy allows;
//! 3. production/cloud-KMS/PKCS#11/HSM/RemoteSigner attestation material
//!    reaches the verifier and fails closed as unavailable;
//! 4. malformed/invalid custody-attestation material fails closed;
//! 5. attestation evidence/input/transcript/provider-identity digests
//!    remain deterministic and domain-bound through wire conversion;
//! 6. rejected cases produce no mutation;
//! 7. MainNet peer-driven apply remains refused even with fixture
//!    attestation;
//! 8. no real KMS/HSM attestation verifier, RemoteSigner backend,
//!    governance execution, or validator-set rotation is claimed.
//!
//! Usage:
//! ```text
//! run_208_custody_attestation_payload_release_binary_helper <OUT_DIR>
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
use qbind_node::pqc_custody_attestation_payload_carrying::{
    callsite_context_for_custody_attestation,
    load_v2_ratification_sidecar_with_custody_attestation_from_bytes,
    mainnet_peer_driven_apply_remains_refused_under_custody_attestation_payload_carrying,
    parse_optional_custody_attestation_sibling_from_json_value,
    route_loaded_custody_attestation_to_live_inbound_0x05_callsite_decision,
    route_loaded_custody_attestation_to_local_peer_candidate_check_callsite_decision,
    route_loaded_custody_attestation_to_peer_driven_drain_callsite_decision,
    route_loaded_custody_attestation_to_reload_apply_callsite_decision,
    route_loaded_custody_attestation_to_reload_check_callsite_decision,
    route_loaded_custody_attestation_to_sighup_callsite_decision,
    route_loaded_custody_attestation_to_startup_p2p_trust_bundle_callsite_decision,
    validate_loaded_lifecycle_custody_and_attestation, verify_loaded_custody_attestation,
    CustodyAttestationCallsiteContext, CustodyAttestationLoadStatus, CustodyAttestationParts,
    CustodyAttestationPayloadCarryingDecisionOutcome, CustodyAttestationPayloadParseError,
    CustodyAttestationPayloadWire, CustodyAttestationWireParseError,
    CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD, CUSTODY_ATTESTATION_PAYLOAD_WIRE_SCHEMA_VERSION,
};
use qbind_node::pqc_custody_attestation_verifier::{
    attestation_transcript_digest, CustodyAttestationClass, CustodyAttestationEvidence,
    CustodyAttestationInput, CustodyAttestationOutcome, CustodyAttestationPolicy,
    CustodyMetadataAttestationOutcome, CUSTODY_ATTESTATION_INVALID_COMMITMENT_SENTINEL,
    CUSTODY_ATTESTATION_SUPPORTED_VERSION,
};
use qbind_node::pqc_governance_authority::GovernanceAuthorityClass;
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ---------------------------------------------------------------------------
// Constants — kept structurally identical to the Run 207 source/test
// fixtures so the typed payload-carrying semantics carry over end-to-end in
// release mode.
// ---------------------------------------------------------------------------

const KEY_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEY_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ROOT_FP: &str = "1111111111111111111111111111111111111111";
const CHAIN_ID: &str = "0000000000000001";
const GENESIS_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const PRIOR_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const KEY_ID: &str = "attestation-key-id-208";
const PROVIDER_ID: &str = "attestation-provider-208";
const ATTEST_COMMITMENT: &str = "attestation-commitment-208";
const ATTEST_NONCE: &str = "attestation-nonce-208";
const GOV_PROOF_DIGEST: &str = "gov-proof-digest-208";
const NOW: u64 = 1_700_000_000;
const FRESH: u64 = 1_699_999_900;
const EXPIRES: u64 = 1_700_001_000;
const ISSUED: u64 = 1_699_999_950;
const WINDOW_SINCE: u64 = 1_699_999_000;
const WINDOW_UNTIL: u64 = 1_700_000_500;

// ---------------------------------------------------------------------------
// Fixture builders — mirror the Run 207 source/test corpus.
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
        custody_backend_kind: Some("fixture-kms".to_string()),
        backend_provider_signer_id: PROVIDER_ID.to_string(),
        custody_key_id: KEY_ID.to_string(),
        suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        lifecycle_action: LocalLifecycleAction::Rotate,
        candidate_digest: DIGEST_2.to_string(),
        authority_domain_sequence: 2,
        governance_proof_digest: Some(GOV_PROOF_DIGEST.to_string()),
        request_digest: Some("request-digest".to_string()),
        response_digest: Some("response-digest".to_string()),
        transcript_digest: Some("transcript-digest".to_string()),
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
        expected_transcript_digest: Some("transcript-digest".to_string()),
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

/// A complete, valid accepted scenario on the given environment. Holds
/// every owned value a case needs to construct a call-site context and a
/// loaded carrier, and to mutate one field for a rejection vector.
struct Scenario {
    domain: AuthorityTrustDomain,
    candidate: PersistentAuthorityStateRecordV2,
    prior: PersistentAuthorityStateRecordVersioned,
    custody: AuthorityCustodyAttestation,
    evidence: CustodyAttestationEvidence,
    input: CustodyAttestationInput,
}

fn accepted_scenario(env: TrustBundleEnvironment) -> Scenario {
    let candidate = rotate_candidate(env);
    let evidence = evidence(CustodyAttestationClass::FixtureAttestation, env, &candidate);
    let input = input(env, &candidate);
    let custody = good_custody_attestation(env, &candidate);
    let prior = prior_versioned(env);
    Scenario { domain: domain(env), candidate, prior, custody, evidence, input }
}

impl Scenario {
    fn parts(&self) -> CustodyAttestationParts {
        CustodyAttestationParts { evidence: self.evidence.clone(), input: self.input.clone() }
    }

    fn loaded(&self) -> CustodyAttestationLoadStatus {
        CustodyAttestationLoadStatus::Available(self.parts())
    }

    fn ctx(
        &self,
        custody_policy: AuthorityCustodyPolicy,
        attestation_policy: CustodyAttestationPolicy,
    ) -> CustodyAttestationCallsiteContext<'_> {
        callsite_context_for_custody_attestation(
            &self.custody,
            Some(&self.prior),
            &self.candidate,
            &self.domain,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::Rotate,
            DIGEST_2,
            2,
            Some(KEY_ID),
            custody_policy,
            attestation_policy,
            NOW,
        )
    }

    /// Default accepted-path context: fixture custody + fixture attestation.
    fn fixture_ctx(&self) -> CustodyAttestationCallsiteContext<'_> {
        self.ctx(
            AuthorityCustodyPolicy::FixtureOnly,
            CustodyAttestationPolicy::FixtureAttestationAllowed,
        )
    }
}

/// Build a wire form from parts and round-trip it through a JSON sibling
/// value, returning the parsed load status. Exercises the full
/// serialize/deserialize path.
fn loaded_via_json(parts: &CustodyAttestationParts) -> CustodyAttestationLoadStatus {
    let wire = CustodyAttestationPayloadWire::from_parts(&parts.evidence, &parts.input);
    let value = serde_json::json!({
        CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD: serde_json::to_value(&wire).unwrap()
    });
    parse_optional_custody_attestation_sibling_from_json_value(&value)
}

// ---------------------------------------------------------------------------
// Typed-outcome tagging — short, stable strings for the evidence tables.
// ---------------------------------------------------------------------------

fn decision_tag(outcome: &CustodyAttestationPayloadCarryingDecisionOutcome) -> String {
    use CustodyAttestationPayloadCarryingDecisionOutcome as D;
    match outcome {
        D::MalformedCustodyAttestationPayload(_) => "reject:MalformedCustodyAttestationPayload",
        D::CustodyAttestationRequiredButAbsent { .. } => {
            "reject:CustodyAttestationRequiredButAbsent"
        }
        D::NoCustodyAttestationSupplied => "bypass:NoCustodyAttestationSupplied",
        D::MainNetPeerDrivenApplyRefused => "reject:MainNetPeerDrivenApplyRefused",
        D::Callsite(o) => return format!("callsite:{}", composition_tag(o)),
    }
    .to_string()
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

/// Extract the routed inner attestation outcome from a reject decision.
fn routed_attestation(
    outcome: &CustodyAttestationPayloadCarryingDecisionOutcome,
) -> Option<&CustodyAttestationOutcome> {
    match outcome.callsite_outcome() {
        Some(CustodyMetadataAttestationOutcome::AttestationRejected { attestation_outcome, .. }) => {
            Some(attestation_outcome)
        }
        _ => None,
    }
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
        Table { name, rows: String::new(), expected: String::new(), actual: String::new(), pass: 0, fail: 0 }
    }

    /// Record an equality check on a typed-outcome tag.
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

    // A1 — legacy no-attestation payload compatible under Disabled.
    {
        let s = accepted_scenario(Env::Devnet);
        let ctx = s.ctx(AuthorityCustodyPolicy::FixtureOnly, CustodyAttestationPolicy::Disabled);
        let outcome = route_loaded_custody_attestation_to_reload_check_callsite_decision(
            &ctx,
            &CustodyAttestationLoadStatus::Absent,
        );
        t.check("A1", "bypass:NoCustodyAttestationSupplied", &decision_tag(&outcome));
        t.assert_true("A1.bypassed", outcome.is_bypassed() && !outcome.is_reject(), "");
    }

    // A2 — DevNet fixture attestation carried through reload-check (via JSON).
    {
        let s = accepted_scenario(Env::Devnet);
        let loaded = loaded_via_json(&s.parts());
        t.assert_true("A2.available", loaded.is_available(), "");
        let ctx = s.fixture_ctx();
        let outcome =
            route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
        t.check("A2", "callsite:accept:Accepted", &decision_tag(&outcome));
    }

    // A3 — TestNet fixture attestation carried through reload-check (via JSON).
    {
        let s = accepted_scenario(Env::Testnet);
        let loaded = loaded_via_json(&s.parts());
        let ctx = s.fixture_ctx();
        let outcome =
            route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
        t.check("A3", "callsite:accept:Accepted", &decision_tag(&outcome));
    }

    // A4 — DevNet fixture attestation carried through reload-apply preflight.
    {
        let s = accepted_scenario(Env::Devnet);
        let loaded = s.loaded();
        let ctx = s.fixture_ctx();
        let outcome =
            route_loaded_custody_attestation_to_reload_apply_callsite_decision(&ctx, &loaded);
        t.check("A4", "callsite:accept:Accepted", &decision_tag(&outcome));
        t.assert_true(
            "A4.accepted",
            matches!(
                outcome.callsite_outcome(),
                Some(CustodyMetadataAttestationOutcome::Accepted { .. })
            ),
            "",
        );
    }

    // A5–A8 — digest determinism through wire conversion.
    {
        let s = accepted_scenario(Env::Devnet);
        let loaded = loaded_via_json(&s.parts());
        let parts = loaded.as_parts().expect("available");
        t.assert_true(
            "A5.evidence_digest",
            parts.evidence.evidence_digest() == s.evidence.evidence_digest(),
            "",
        );
        t.assert_true(
            "A6.input_digest",
            parts.input.input_digest() == s.input.input_digest(),
            "",
        );
        let before =
            attestation_transcript_digest(&s.evidence.evidence_digest(), &s.input.input_digest());
        let after = attestation_transcript_digest(
            &parts.evidence.evidence_digest(),
            &parts.input.input_digest(),
        );
        t.assert_true("A7.transcript_digest", before == after, "");
        t.assert_true(
            "A8.provider_identity_digest",
            parts.evidence.provider_identity_digest() == s.evidence.provider_identity_digest(),
            "",
        );
    }

    // A9 — fixture attestation routes to the Run 205 verifier when present.
    {
        let s = accepted_scenario(Env::Devnet);
        let loaded = s.loaded();
        let ctx = s.fixture_ctx();
        let outcome = verify_loaded_custody_attestation(&ctx, &loaded);
        let tag = outcome.as_ref().map(attestation_tag).unwrap_or_else(|| "none".to_string());
        t.check("A9", "accept:FixtureAttestationAccepted", &tag);
    }

    // A10 — combined lifecycle + custody + fixture attestation for DevNet.
    {
        let s = accepted_scenario(Env::Devnet);
        let loaded = s.loaded();
        let ctx = s.fixture_ctx();
        let outcome = validate_loaded_lifecycle_custody_and_attestation(&ctx, &loaded, false);
        let tag = outcome.as_ref().map(composition_tag).unwrap_or_else(|| "none".to_string());
        t.check("A10", "accept:Accepted", &tag);
    }

    // A11 — composes with the Run 203 fixture KMS backend context.
    {
        let mut s = accepted_scenario(Env::Devnet);
        s.evidence.custody_backend_kind = Some("fixture-kms".to_string());
        s.evidence.custody_class = AuthorityCustodyClass::Kms;
        s.input.expected_custody_class = AuthorityCustodyClass::Kms;
        let loaded = loaded_via_json(&s.parts());
        let ctx = s.fixture_ctx();
        let outcome =
            route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
        t.check("A11", "callsite:accept:Accepted", &decision_tag(&outcome));
    }

    // A12 — composes with the Run 203 fixture HSM backend context.
    {
        let mut s = accepted_scenario(Env::Devnet);
        s.evidence.custody_backend_kind = Some("fixture-hsm".to_string());
        s.evidence.custody_class = AuthorityCustodyClass::Hsm;
        s.input.expected_custody_class = AuthorityCustodyClass::Hsm;
        let loaded = loaded_via_json(&s.parts());
        let ctx = s.fixture_ctx();
        let outcome =
            route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
        t.check("A12", "callsite:accept:Accepted", &decision_tag(&outcome));
    }

    // A13 — composes with the Run 201 fixture RemoteSigner transport context.
    {
        let mut s = accepted_scenario(Env::Devnet);
        s.evidence.custody_backend_kind = Some("fixture-remote-signer".to_string());
        s.evidence.custody_class = AuthorityCustodyClass::RemoteSigner;
        s.input.expected_custody_class = AuthorityCustodyClass::RemoteSigner;
        let loaded = loaded_via_json(&s.parts());
        let ctx = s.fixture_ctx();
        let outcome =
            route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
        t.check("A13", "callsite:accept:Accepted", &decision_tag(&outcome));
    }

    // A14 — governance proof behavior unchanged when attestation Disabled.
    for gov in [
        GovernanceAuthorityClass::GenesisBound,
        GovernanceAuthorityClass::EmergencyCouncil,
        GovernanceAuthorityClass::OnChainGovernance,
    ] {
        let s = accepted_scenario(Env::Devnet);
        let ctx = callsite_context_for_custody_attestation(
            &s.custody,
            Some(&s.prior),
            &s.candidate,
            &s.domain,
            gov,
            LocalLifecycleAction::Rotate,
            DIGEST_2,
            2,
            Some(KEY_ID),
            AuthorityCustodyPolicy::FixtureOnly,
            CustodyAttestationPolicy::Disabled,
            NOW,
        );
        let outcome = route_loaded_custody_attestation_to_reload_check_callsite_decision(
            &ctx,
            &CustodyAttestationLoadStatus::Absent,
        );
        t.assert_true(&format!("A14.{gov:?}"), outcome.is_bypassed(), "");
    }

    // A15 — production attestation reaches verifier and returns unavailable.
    {
        let mut s = accepted_scenario(Env::Devnet);
        s.evidence.attestation_class = CustodyAttestationClass::ProductionAttestationUnavailable;
        let loaded = loaded_via_json(&s.parts());
        let ctx = s.ctx(
            AuthorityCustodyPolicy::FixtureOnly,
            CustodyAttestationPolicy::ProductionAttestationRequired,
        );
        let outcome =
            route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
        let unavailable = routed_attestation(&outcome).map(|o| o.is_unavailable()).unwrap_or(false);
        t.assert_true("A15", !outcome.is_accept() && unavailable, "");
    }

    t.finish(out)
}

// ---------------------------------------------------------------------------
// Table 2 — rejection cases R1..R43.
// ---------------------------------------------------------------------------

/// Mutate the carried evidence/input via the closure, route through the
/// reload-check call-site under the fixture policies, and return the routed
/// inner attestation outcome (panics if not a verifier reject).
fn assert_attestation_rejected(mutate: impl FnOnce(&mut Scenario)) -> CustodyAttestationOutcome {
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    mutate(&mut s);
    let loaded = s.loaded();
    let ctx = s.fixture_ctx();
    let outcome = route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    routed_attestation(&outcome)
        .cloned()
        .unwrap_or_else(|| panic!("expected AttestationRejected, got {outcome:?}"))
}

fn run_rejection_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("rejection");

    // R1 — absent under a required policy rejected fail-closed.
    {
        let s = accepted_scenario(Env::Devnet);
        let ctx = s.ctx(
            AuthorityCustodyPolicy::FixtureOnly,
            CustodyAttestationPolicy::ProductionAttestationRequired,
        );
        let outcome = route_loaded_custody_attestation_to_reload_check_callsite_decision(
            &ctx,
            &CustodyAttestationLoadStatus::Absent,
        );
        t.check("R1", "reject:CustodyAttestationRequiredButAbsent", &decision_tag(&outcome));
        t.assert_true("R1.flags", outcome.is_required_but_absent() && outcome.is_reject(), "");
    }

    // R2 — malformed evidence (empty required field) rejected.
    {
        let s = accepted_scenario(Env::Devnet);
        let mut wire = CustodyAttestationPayloadWire::from_parts(&s.evidence, &s.input);
        wire.evidence.candidate_digest = String::new();
        let value = serde_json::json!({
            CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD: serde_json::to_value(&wire).unwrap()
        });
        let loaded = parse_optional_custody_attestation_sibling_from_json_value(&value);
        t.assert_true("R2.malformed", loaded.is_malformed(), "");
        let ctx = s.fixture_ctx();
        let outcome =
            route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
        t.assert_true("R2", outcome.is_malformed_payload() && outcome.is_reject(), "");
    }

    // R3 — malformed input (empty required field) rejected.
    {
        let s = accepted_scenario(Env::Devnet);
        let mut wire = CustodyAttestationPayloadWire::from_parts(&s.evidence, &s.input);
        wire.input.expected_attestation_nonce = String::new();
        let value = serde_json::json!({
            CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD: serde_json::to_value(&wire).unwrap()
        });
        let loaded = parse_optional_custody_attestation_sibling_from_json_value(&value);
        t.assert_true("R3", loaded.is_malformed(), "");
    }

    // R4 — malformed combined payload (sibling not an object) rejected.
    {
        let value = serde_json::json!({ CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD: "not-an-object" });
        let loaded = parse_optional_custody_attestation_sibling_from_json_value(&value);
        t.assert_true("R4", loaded.is_malformed(), "");
    }

    // R5 — unsupported future schema version rejected.
    {
        let s = accepted_scenario(Env::Devnet);
        let mut wire = CustodyAttestationPayloadWire::from_parts(&s.evidence, &s.input);
        wire.schema_version = 9_999;
        let value = serde_json::json!({
            CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD: serde_json::to_value(&wire).unwrap()
        });
        let loaded = parse_optional_custody_attestation_sibling_from_json_value(&value);
        let is_unknown_version = matches!(
            loaded.malformed_error(),
            Some(CustodyAttestationPayloadParseError::Wire(
                CustodyAttestationWireParseError::UnknownSchemaVersion { got: 9_999, .. }
            ))
        );
        t.assert_true("R5", is_unknown_version, "");
    }

    // R6 / R7 — fixture rejected under production-required policies.
    {
        let s = accepted_scenario(Env::Devnet);
        let loaded = s.loaded();
        let ctx = s.ctx(
            AuthorityCustodyPolicy::FixtureOnly,
            CustodyAttestationPolicy::ProductionAttestationRequired,
        );
        let outcome =
            route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
        let tag = routed_attestation(&outcome).map(attestation_tag).unwrap_or_default();
        t.check("R6", "reject:FixtureRejectedProductionRequired", &tag);
    }
    {
        let s = accepted_scenario(Env::Devnet);
        let loaded = s.loaded();
        let ctx = s.ctx(
            AuthorityCustodyPolicy::FixtureOnly,
            CustodyAttestationPolicy::MainnetProductionAttestationRequired,
        );
        let outcome =
            route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
        let tag = routed_attestation(&outcome).map(attestation_tag).unwrap_or_default();
        t.check("R7", "reject:FixtureRejectedMainnetProductionRequired", &tag);
    }

    // R8–R13 — production-class attestations rejected as unavailable.
    let unavailable_cases: &[(&str, CustodyAttestationClass, CustodyAttestationPolicy)] = &[
        ("R8", CustodyAttestationClass::RemoteSignerAttestation, CustodyAttestationPolicy::FixtureAttestationAllowed),
        ("R9", CustodyAttestationClass::KmsAttestation, CustodyAttestationPolicy::FixtureAttestationAllowed),
        ("R10", CustodyAttestationClass::HsmAttestation, CustodyAttestationPolicy::FixtureAttestationAllowed),
        ("R11", CustodyAttestationClass::CloudKmsAttestationUnavailable, CustodyAttestationPolicy::FixtureAttestationAllowed),
        ("R12", CustodyAttestationClass::Pkcs11HsmAttestationUnavailable, CustodyAttestationPolicy::FixtureAttestationAllowed),
        ("R13", CustodyAttestationClass::ProductionAttestationUnavailable, CustodyAttestationPolicy::ProductionAttestationRequired),
    ];
    for (id, class, policy) in unavailable_cases {
        let mut s = accepted_scenario(Env::Devnet);
        s.evidence.attestation_class = *class;
        let loaded = s.loaded();
        let ctx = s.ctx(AuthorityCustodyPolicy::FixtureOnly, *policy);
        let outcome =
            route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
        let unavailable = routed_attestation(&outcome).map(|o| o.is_unavailable()).unwrap_or(false);
        t.assert_true(id, !outcome.is_accept() && unavailable, "");
    }

    // R14 — MainNet production attestation rejected as unavailable.
    {
        let mut s = accepted_scenario(Env::Devnet);
        s.evidence.attestation_class = CustodyAttestationClass::ProductionAttestationUnavailable;
        let loaded = s.loaded();
        let ctx = s.ctx(
            AuthorityCustodyPolicy::FixtureOnly,
            CustodyAttestationPolicy::MainnetProductionAttestationRequired,
        );
        let outcome =
            route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
        let tag = routed_attestation(&outcome).map(attestation_tag).unwrap_or_default();
        t.check("R14", "reject:MainNetProductionAttestationUnavailable", &tag);
    }

    // R15 — unknown attestation class rejected.
    {
        let mut s = accepted_scenario(Env::Devnet);
        s.evidence.attestation_class = CustodyAttestationClass::Unknown;
        let loaded = loaded_via_json(&s.parts());
        let ctx = s.fixture_ctx();
        let outcome =
            route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
        let tag = routed_attestation(&outcome).map(attestation_tag).unwrap_or_default();
        t.check("R15", "reject:UnknownAttestationClassRejected", &tag);
    }

    // R16–R34 — wrong-binding rejections route through the Run 205 verifier.
    t.check(
        "R16",
        "reject:WrongEnvironment",
        &attestation_tag(&assert_attestation_rejected(|s| {
            s.evidence.environment = TrustBundleEnvironment::Testnet;
        })),
    );
    t.check(
        "R17",
        "reject:WrongChain",
        &attestation_tag(&assert_attestation_rejected(|s| {
            s.evidence.chain_id = "deadbeef".to_string();
            s.input.expected_chain_id = "deadbeef".to_string();
        })),
    );
    t.check(
        "R18",
        "reject:WrongGenesis",
        &attestation_tag(&assert_attestation_rejected(|s| {
            s.evidence.genesis_hash = "ff".repeat(32);
            s.input.expected_genesis_hash = "ff".repeat(32);
        })),
    );
    t.check(
        "R19",
        "reject:WrongAuthorityRoot",
        &attestation_tag(&assert_attestation_rejected(|s| {
            s.evidence.authority_root_fingerprint = "9".repeat(40);
            s.input.expected_authority_root_fingerprint = "9".repeat(40);
        })),
    );
    t.check(
        "R20",
        "reject:WrongSigningKeyFingerprint",
        &attestation_tag(&assert_attestation_rejected(|s| {
            s.evidence.bundle_signing_key_fingerprint = "0".repeat(40);
        })),
    );
    t.check(
        "R21",
        "reject:WrongCustodyClass",
        &attestation_tag(&assert_attestation_rejected(|s| {
            s.evidence.custody_class = AuthorityCustodyClass::Hsm;
        })),
    );
    t.check(
        "R22",
        "reject:WrongBackendProviderSignerId",
        &attestation_tag(&assert_attestation_rejected(|s| {
            s.evidence.backend_provider_signer_id = "other-provider".to_string();
        })),
    );
    t.check(
        "R23",
        "reject:WrongKeyId",
        &attestation_tag(&assert_attestation_rejected(|s| {
            s.evidence.custody_key_id = "other-key".to_string();
        })),
    );
    t.check(
        "R24",
        "reject:WrongSuite",
        &attestation_tag(&assert_attestation_rejected(|s| {
            s.evidence.suite_id = 99;
        })),
    );
    t.check(
        "R25",
        "reject:WrongLifecycleAction",
        &attestation_tag(&assert_attestation_rejected(|s| {
            s.evidence.lifecycle_action = LocalLifecycleAction::Revoke;
        })),
    );
    t.check(
        "R26",
        "reject:WrongCandidateDigest",
        &attestation_tag(&assert_attestation_rejected(|s| {
            s.evidence.candidate_digest = "3".repeat(64);
        })),
    );
    t.check(
        "R27",
        "reject:WrongAuthorityDomainSequence",
        &attestation_tag(&assert_attestation_rejected(|s| {
            s.evidence.authority_domain_sequence = 9;
        })),
    );
    t.check(
        "R28",
        "reject:WrongGovernanceProofDigest",
        &attestation_tag(&assert_attestation_rejected(|s| {
            s.evidence.governance_proof_digest = Some("other-gov-proof".to_string());
        })),
    );
    t.check(
        "R29",
        "reject:WrongRequestDigest",
        &attestation_tag(&assert_attestation_rejected(|s| {
            s.evidence.request_digest = Some("other-request".to_string());
        })),
    );
    t.check(
        "R30",
        "reject:WrongResponseDigest",
        &attestation_tag(&assert_attestation_rejected(|s| {
            s.evidence.response_digest = Some("other-response".to_string());
        })),
    );
    t.check(
        "R31",
        "reject:WrongTranscriptDigest",
        &attestation_tag(&assert_attestation_rejected(|s| {
            s.evidence.transcript_digest = Some("other-transcript".to_string());
        })),
    );
    t.check(
        "R32",
        "reject:StaleOrReplayedAttestation",
        &attestation_tag(&assert_attestation_rejected(|s| {
            s.evidence.attestation_nonce = "stale-nonce".to_string();
        })),
    );
    t.check(
        "R33",
        "reject:ExpiredAttestation",
        &attestation_tag(&assert_attestation_rejected(|s| {
            s.evidence.freshness_unix = Some(1);
            s.evidence.expires_at_unix = Some(2);
        })),
    );
    t.check(
        "R34",
        "reject:InvalidAttestationCommitment",
        &attestation_tag(&assert_attestation_rejected(|s| {
            s.evidence.attestation_commitment =
                CUSTODY_ATTESTATION_INVALID_COMMITMENT_SENTINEL.to_string();
        })),
    );

    // R35 — local operator cannot satisfy production attestation.
    {
        let s = accepted_scenario(Env::Devnet);
        let loaded = s.loaded();
        let ctx = s.ctx(
            AuthorityCustodyPolicy::FixtureOnly,
            CustodyAttestationPolicy::ProductionAttestationRequired,
        );
        let outcome =
            route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
        t.assert_true("R35", !outcome.is_accept(), "");
    }

    // R36 — peer majority cannot satisfy production attestation.
    {
        let mut s = accepted_scenario(Env::Devnet);
        s.evidence.attestation_class = CustodyAttestationClass::ProductionAttestationUnavailable;
        let loaded = s.loaded();
        let ctx = s.ctx(
            AuthorityCustodyPolicy::FixtureOnly,
            CustodyAttestationPolicy::ProductionAttestationRequired,
        );
        let outcome =
            route_loaded_custody_attestation_to_peer_driven_drain_callsite_decision(&ctx, &loaded);
        t.assert_true("R36", !outcome.is_accept(), "");
    }

    // R37 — attestation valid but custody metadata invalid rejected.
    {
        let mut s = accepted_scenario(Env::Devnet);
        s.custody.candidate_digest = "bad-digest".to_string();
        let loaded = s.loaded();
        let ctx = s.fixture_ctx();
        let outcome =
            route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
        t.assert_true(
            "R37",
            !outcome.is_accept()
                && matches!(
                    outcome.callsite_outcome(),
                    Some(CustodyMetadataAttestationOutcome::LifecycleOrCustodyRejected(_))
                ),
            "",
        );
    }

    // R38 — custody valid but attestation invalid rejected.
    t.check(
        "R38",
        "reject:InvalidAttestationCommitment",
        &attestation_tag(&assert_attestation_rejected(|s| {
            s.evidence.attestation_commitment =
                CUSTODY_ATTESTATION_INVALID_COMMITMENT_SENTINEL.to_string();
        })),
    );

    // R39 — lifecycle + governance + custody valid but production
    //       attestation unavailable rejected overall (reload-apply path).
    {
        let mut s = accepted_scenario(Env::Devnet);
        s.evidence.attestation_class = CustodyAttestationClass::KmsAttestation;
        let loaded = s.loaded();
        let ctx =
            s.ctx(AuthorityCustodyPolicy::FixtureOnly, CustodyAttestationPolicy::KmsAttestationRequired);
        let outcome =
            route_loaded_custody_attestation_to_reload_apply_callsite_decision(&ctx, &loaded);
        let unavailable = routed_attestation(&outcome).map(|o| o.is_unavailable()).unwrap_or(false);
        t.assert_true("R39", !outcome.is_accept() && unavailable, "");
    }

    // R40 — validation-only rejection is pure (stable repeat results).
    {
        let s = accepted_scenario(Env::Devnet);
        let loaded = s.loaded();
        let ctx = s.ctx(
            AuthorityCustodyPolicy::FixtureOnly,
            CustodyAttestationPolicy::ProductionAttestationRequired,
        );
        let first = route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
        let again = route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
        t.assert_true("R40", first == again, "");
    }

    // R41 — mutating-preflight routing helpers are pure and accept the
    //        fixture carrier without any mutation.
    {
        let s = accepted_scenario(Env::Devnet);
        let loaded = s.loaded();
        let ctx = s.fixture_ctx();
        let a = route_loaded_custody_attestation_to_reload_apply_callsite_decision(&ctx, &loaded);
        let b = route_loaded_custody_attestation_to_sighup_callsite_decision(&ctx, &loaded);
        let c = route_loaded_custody_attestation_to_startup_p2p_trust_bundle_callsite_decision(
            &ctx, &loaded,
        );
        t.assert_true("R41", a.is_accept() && b.is_accept() && c.is_accept(), "");
    }

    // R42 — invalid live 0x05 custody-attestation candidate not propagated.
    {
        let s = accepted_scenario(Env::Devnet);
        let mut wire = CustodyAttestationPayloadWire::from_parts(&s.evidence, &s.input);
        wire.evidence.attestation_commitment = String::new();
        let value = serde_json::json!({
            CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD: serde_json::to_value(&wire).unwrap()
        });
        let loaded = parse_optional_custody_attestation_sibling_from_json_value(&value);
        let ctx = s.fixture_ctx();
        let outcome =
            route_loaded_custody_attestation_to_live_inbound_0x05_callsite_decision(&ctx, &loaded);
        t.assert_true("R42", outcome.is_malformed_payload() && outcome.is_reject(), "");
    }

    // R43 — MainNet peer-driven apply refused even with fixture attestation.
    {
        let s = accepted_scenario(Env::Mainnet);
        let loaded = s.loaded();
        let ctx = s.fixture_ctx();
        let outcome =
            route_loaded_custody_attestation_to_peer_driven_drain_callsite_decision(&ctx, &loaded);
        t.check("R43", "reject:MainNetPeerDrivenApplyRefused", &decision_tag(&outcome));
        t.assert_true(
            "R43.helper",
            outcome.is_mainnet_peer_driven_apply_refused()
                && mainnet_peer_driven_apply_remains_refused_under_custody_attestation_payload_carrying(
                    TrustBundleEnvironment::Mainnet,
                ),
            "",
        );
    }

    t.finish(out)
}

// ---------------------------------------------------------------------------
// Table 3 — serde / combined-loader compatibility.
// ---------------------------------------------------------------------------

/// Mint a real signed v2 ratification sidecar JSON value with an optional
/// `custody_attestation` sibling, mirroring the Run 207 source/test helper.
fn make_v2_sidecar_value(
    env: TrustBundleEnvironment,
    custody_sibling: Option<serde_json::Value>,
) -> serde_json::Value {
    use qbind_crypto::MlDsa44Backend;
    use qbind_ledger::bundle_signing_ratification::v2_test_helpers::build_signed_ratification_v2;
    use qbind_ledger::genesis::GENESIS_AUTHORITY_SUITE_ML_DSA_44;
    use qbind_ledger::RatificationEnvironment;

    let ratification_env = match env {
        TrustBundleEnvironment::Mainnet => RatificationEnvironment::Mainnet,
        TrustBundleEnvironment::Testnet => RatificationEnvironment::Testnet,
        TrustBundleEnvironment::Devnet => RatificationEnvironment::Devnet,
    };
    let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
    let (target_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
    let mut auth_pk_hex = String::with_capacity(auth_pk.len() * 2);
    for b in &auth_pk {
        use std::fmt::Write;
        let _ = write!(&mut auth_pk_hex, "{:02x}", b);
    }
    let genesis_hash: qbind_ledger::genesis::GenesisHash = [0xaa; 32];
    let v2 = build_signed_ratification_v2(
        CHAIN_ID,
        ratification_env,
        genesis_hash,
        GENESIS_AUTHORITY_SUITE_ML_DSA_44 as u32,
        &auth_pk_hex,
        &auth_sk,
        &target_pk,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(KEY_A.to_string()),
        Some(DIGEST_2.to_string()),
        None,
        None,
        None,
        None,
    );
    let mut value = serde_json::to_value(&v2).expect("ratification serializes");
    if let Some(p) = custody_sibling {
        value
            .as_object_mut()
            .unwrap()
            .insert(CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD.to_string(), p);
    }
    value
}

fn run_loader_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("loader");

    // L1 — legacy v2 sidecar without sibling yields Absent.
    {
        let value = make_v2_sidecar_value(Env::Devnet, None);
        let bytes = serde_json::to_vec(&value).unwrap();
        let path = PathBuf::from("/dev/null/run-208-legacy.json");
        let loaded = load_v2_ratification_sidecar_with_custody_attestation_from_bytes(&bytes, &path)
            .expect("legacy v2 sidecar parses");
        t.assert_true("L1", loaded.custody_attestation.is_absent(), "");
    }

    // L2 — v2 sidecar with custody sibling yields Available and matching parts.
    {
        let s = accepted_scenario(Env::Devnet);
        let wire = CustodyAttestationPayloadWire::from_parts(&s.evidence, &s.input);
        let value =
            make_v2_sidecar_value(Env::Devnet, Some(serde_json::to_value(&wire).unwrap()));
        let bytes = serde_json::to_vec(&value).unwrap();
        let path = PathBuf::from("/dev/null/run-208-carry.json");
        let loaded = load_v2_ratification_sidecar_with_custody_attestation_from_bytes(&bytes, &path)
            .expect("v2 sidecar with sibling parses");
        t.assert_true(
            "L2",
            loaded.custody_attestation.is_available()
                && loaded.custody_attestation.as_parts() == Some(&s.parts()),
            "",
        );
    }

    // L3 — v2 sidecar with malformed sibling yields Malformed while the
    //      ratification still parses.
    {
        let value = make_v2_sidecar_value(
            Env::Devnet,
            Some(serde_json::json!({ "schema_version": 9_999 })),
        );
        let bytes = serde_json::to_vec(&value).unwrap();
        let path = PathBuf::from("/dev/null/run-208-malformed.json");
        let loaded = load_v2_ratification_sidecar_with_custody_attestation_from_bytes(&bytes, &path)
            .expect("v2 ratification still parses");
        t.assert_true("L3", loaded.custody_attestation.is_malformed(), "");
    }

    // L4 — canonical sibling field name + schema version.
    t.check("L4.field", "custody_attestation", CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD);
    t.check("L4.version", "1", &CUSTODY_ATTESTATION_PAYLOAD_WIRE_SCHEMA_VERSION.to_string());

    // L5 — absent sibling when field missing or explicitly null.
    {
        let missing = serde_json::json!({ "schema_version": 2 });
        let null = serde_json::json!({ CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD: null });
        t.assert_true(
            "L5",
            parse_optional_custody_attestation_sibling_from_json_value(&missing).is_absent()
                && parse_optional_custody_attestation_sibling_from_json_value(&null).is_absent(),
            "",
        );
    }

    t.finish(out)
}

// ---------------------------------------------------------------------------
// Table 4 — determinism through wire conversion + stable routing.
// ---------------------------------------------------------------------------

fn run_determinism_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("determinism");

    let s = accepted_scenario(Env::Devnet);
    // Repeat wire round-trips and assert byte-identical digests every time.
    let mut ev = String::new();
    let mut inp = String::new();
    let mut tr = String::new();
    let mut pr = String::new();
    let mut stable = true;
    for i in 0..8 {
        let loaded = loaded_via_json(&s.parts());
        let parts = loaded.as_parts().expect("available");
        let e = parts.evidence.evidence_digest();
        let n = parts.input.input_digest();
        let transcript = attestation_transcript_digest(&e, &n);
        let provider = parts.evidence.provider_identity_digest();
        if i == 0 {
            ev = e;
            inp = n;
            tr = transcript;
            pr = provider;
        } else {
            stable &= ev == e && inp == n && tr == transcript && pr == provider;
        }
    }
    t.assert_true("D1.digests_stable", stable, "");
    t.assert_true("D2.bound_to_source", ev == s.evidence.evidence_digest(), "");

    // Routing outcome is stable across repeats for a rejecting policy.
    let loaded = s.loaded();
    let ctx = s.ctx(
        AuthorityCustodyPolicy::FixtureOnly,
        CustodyAttestationPolicy::ProductionAttestationRequired,
    );
    let r1 = route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    let r2 = route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded);
    t.assert_true("D3.routing_stable", r1 == r2, "");

    t.finish(out)
}

// ---------------------------------------------------------------------------
// Table 5 — MainNet refusal + per-surface reachability.
// ---------------------------------------------------------------------------

fn run_refusal_reachability_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("refusal_reachability");

    // The surface MainNet-refusal helper.
    t.assert_true(
        "M1.mainnet_refused",
        mainnet_peer_driven_apply_remains_refused_under_custody_attestation_payload_carrying(
            Env::Mainnet,
        ),
        "",
    );
    t.assert_true(
        "M2.devnet_not_refused",
        !mainnet_peer_driven_apply_remains_refused_under_custody_attestation_payload_carrying(
            Env::Devnet,
        ),
        "",
    );
    t.assert_true(
        "M3.testnet_not_refused",
        !mainnet_peer_driven_apply_remains_refused_under_custody_attestation_payload_carrying(
            Env::Testnet,
        ),
        "",
    );

    // Each of the seven production surfaces reaches the Run 205 verifier and
    // accepts the fixture carrier on DevNet.
    let s = accepted_scenario(Env::Devnet);
    let loaded = s.loaded();
    let ctx = s.fixture_ctx();
    t.assert_true(
        "S1.reload_check",
        route_loaded_custody_attestation_to_reload_check_callsite_decision(&ctx, &loaded)
            .is_accept(),
        "",
    );
    t.assert_true(
        "S2.reload_apply",
        route_loaded_custody_attestation_to_reload_apply_callsite_decision(&ctx, &loaded)
            .is_accept(),
        "",
    );
    t.assert_true(
        "S3.startup_p2p_trust_bundle",
        route_loaded_custody_attestation_to_startup_p2p_trust_bundle_callsite_decision(
            &ctx, &loaded,
        )
        .is_accept(),
        "",
    );
    t.assert_true(
        "S4.sighup",
        route_loaded_custody_attestation_to_sighup_callsite_decision(&ctx, &loaded).is_accept(),
        "",
    );
    t.assert_true(
        "S5.local_peer_candidate_check",
        route_loaded_custody_attestation_to_local_peer_candidate_check_callsite_decision(
            &ctx, &loaded,
        )
        .is_accept(),
        "",
    );
    t.assert_true(
        "S6.live_inbound_0x05",
        route_loaded_custody_attestation_to_live_inbound_0x05_callsite_decision(&ctx, &loaded)
            .is_accept(),
        "",
    );
    t.assert_true(
        "S7.peer_driven_drain_devnet",
        route_loaded_custody_attestation_to_peer_driven_drain_callsite_decision(&ctx, &loaded)
            .is_accept(),
        "",
    );

    t.finish(out)
}

// ---------------------------------------------------------------------------
// Fixture dump — canonical carrier sidecars + digests for the archive.
// ---------------------------------------------------------------------------

fn run_fixture_dump(out: &Path) {
    let dir = out.join("fixtures");
    let s = accepted_scenario(TrustBundleEnvironment::Devnet);

    // Canonical fixture carrier sibling JSON.
    let wire = CustodyAttestationPayloadWire::from_parts(&s.evidence, &s.input);
    let sibling = serde_json::json!({
        CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD: serde_json::to_value(&wire).unwrap()
    });
    write_file(
        &dir.join("custody_attestation_sibling.json"),
        &serde_json::to_string_pretty(&sibling).unwrap(),
    );

    // Full v2 ratification sidecar carrying the custody-attestation sibling.
    let full = make_v2_sidecar_value(
        TrustBundleEnvironment::Devnet,
        Some(serde_json::to_value(&wire).unwrap()),
    );
    write_file(
        &dir.join("v2_ratification_sidecar_with_custody_attestation.json"),
        &serde_json::to_string_pretty(&full).unwrap(),
    );

    write_file(&dir.join("evidence_digest.txt"), &format!("{}\n", s.evidence.evidence_digest()));
    write_file(&dir.join("input_digest.txt"), &format!("{}\n", s.input.input_digest()));
    write_file(
        &dir.join("transcript_digest.txt"),
        &format!(
            "{}\n",
            attestation_transcript_digest(&s.evidence.evidence_digest(), &s.input.input_digest())
        ),
    );
    write_file(
        &dir.join("provider_identity_digest.txt"),
        &format!("{}\n", s.evidence.provider_identity_digest()),
    );
}

fn main() {
    let mut args = env::args().skip(1);
    let out_dir = match args.next() {
        Some(a) => PathBuf::from(a),
        None => {
            eprintln!(
                "usage: run_208_custody_attestation_payload_release_binary_helper <OUT_DIR>"
            );
            std::process::exit(2);
        }
    };
    fs::create_dir_all(&out_dir).unwrap_or_else(|e| panic!("create out dir {out_dir:?}: {e}"));

    let tables: &[(&str, fn(&Path) -> (u64, u64))] = &[
        ("accepted", run_accepted_table),
        ("rejection", run_rejection_table),
        ("loader", run_loader_table),
        ("determinism", run_determinism_table),
        ("refusal_reachability", run_refusal_reachability_table),
    ];

    let mut total_pass = 0u64;
    let mut total_fail = 0u64;
    let mut summary = String::new();
    summary.push_str("run_208_custody_attestation_payload_release_binary_helper\n");
    summary.push_str(
        "scope: Run 207 custody-attestation payload carrying + production-context routing over the Run 205 verifier and Run 188 custody boundary (release binary)\n",
    );
    summary.push_str(
        "note: fixture-only; additive optional custody_attestation sibling; no real cloud-KMS/PKCS#11/HSM-vendor/RemoteSigner attestation verifier; no real KMS/HSM/RemoteSigner backend; no live trust mutation; no P2P socket; production attestation routes to verifier and fails closed; MainNet peer-driven apply remains refused\n\n",
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