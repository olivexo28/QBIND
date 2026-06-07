//! Run 210 — release-built helper that exercises the Run 209 **hidden
//! custody-attestation policy selector** and production-context preflight
//! routing
//! ([`qbind_node::pqc_custody_attestation_policy_surface`]) **in release
//! mode**, layered over the Run 207 custody-attestation payload carrying
//! surface ([`qbind_node::pqc_custody_attestation_payload_carrying`]), the
//! Run 205 production custody-attestation verifier boundary
//! ([`qbind_node::pqc_custody_attestation_verifier`]), and the Run 188
//! authority-custody boundary ([`qbind_node::pqc_authority_custody`]).
//!
//! Per `task/RUN_210_TASK.txt`, Run 210 is the release-binary evidence run
//! for the Run 209 source/test hidden custody-attestation policy selector.
//! This helper is fixture-only tooling and:
//!
//! * does NOT modify any production runtime code, CLI flag, env var, or
//!   wire / marker / sequence / trust-bundle / peer-candidate-envelope
//!   schema beyond what Runs 070, 130–209 already established;
//! * does NOT enable MainNet peer-driven apply on any surface;
//! * does NOT mutate any live trust state, write any marker, advance any
//!   sequence, swap any live trust, evict any session, or invoke Run 070 —
//!   every selector parser, resolver, preflight wrapper, and routing helper
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
//! * exists alongside (and does NOT replace) the Run 209 source/test target
//!   `crates/qbind-node/tests/run_209_custody_attestation_policy_selector_tests.rs`.
//!
//! The helper proves, in release mode through the production library
//! symbols:
//!
//! 1. default behavior (no CLI, no env) resolves to
//!    `CustodyAttestationPolicy::Disabled`;
//! 2. the hidden CLI selector resolves each canonical tag;
//! 3. the hidden env selector resolves each canonical tag;
//! 4. CLI-over-env precedence is deterministic;
//! 5. invalid CLI/env selector values fail closed with typed parse errors;
//! 6. the resolved policy reaches all seven production preflight contexts;
//! 7. fixture attestation passes only where the resolved policy allows;
//! 8. production / cloud-KMS / PKCS#11 / HSM / RemoteSigner attestation
//!    remains fail-closed as unavailable regardless of selector;
//! 9. MainNet peer-driven apply remains refused even with
//!    `MainnetProductionAttestationRequired` and fixture attestation;
//! 10. no real KMS/HSM attestation verifier, RemoteSigner backend,
//!     governance execution, real on-chain proof verifier, or validator-set
//!     rotation is claimed.
//!
//! Usage:
//! ```text
//! run_210_custody_attestation_policy_release_binary_helper <OUT_DIR>
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
    route_loaded_custody_attestation_to_reload_check_callsite_decision,
    CustodyAttestationLoadStatus, CustodyAttestationParts,
    CustodyAttestationPayloadCarryingDecisionOutcome, CustodyAttestationPayloadParseError,
    CustodyAttestationPayloadWire, CustodyAttestationWireParseError,
    CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD, CUSTODY_ATTESTATION_PAYLOAD_WIRE_SCHEMA_VERSION,
};
use qbind_node::pqc_custody_attestation_policy_surface::{
    custody_attestation_policy_env_selector, custody_attestation_policy_from_cli_or_env,
    custody_attestation_policy_from_selector,
    preflight_v2_marker_custody_attestation_for_live_inbound_0x05,
    preflight_v2_marker_custody_attestation_for_local_peer_candidate_check,
    preflight_v2_marker_custody_attestation_for_peer_driven_drain,
    preflight_v2_marker_custody_attestation_for_reload_apply,
    preflight_v2_marker_custody_attestation_for_reload_check,
    preflight_v2_marker_custody_attestation_for_sighup,
    preflight_v2_marker_custody_attestation_for_startup_p2p_trust_bundle,
    CustodyAttestationPolicySelectorParseError,
    CUSTODY_ATTESTATION_POLICY_TAG_DISABLED,
    CUSTODY_ATTESTATION_POLICY_TAG_FIXTURE_ATTESTATION_ALLOWED,
    CUSTODY_ATTESTATION_POLICY_TAG_HSM_ATTESTATION_REQUIRED,
    CUSTODY_ATTESTATION_POLICY_TAG_KMS_ATTESTATION_REQUIRED,
    CUSTODY_ATTESTATION_POLICY_TAG_MAINNET_PRODUCTION_ATTESTATION_REQUIRED,
    CUSTODY_ATTESTATION_POLICY_TAG_PRODUCTION_ATTESTATION_REQUIRED,
    CUSTODY_ATTESTATION_POLICY_TAG_REMOTE_SIGNER_ATTESTATION_REQUIRED,
    QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY_ENV,
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
// Constants — kept structurally identical to the Run 207/208 source/test
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
const KEY_ID: &str = "attestation-key-id-210";
const PROVIDER_ID: &str = "attestation-provider-210";
const ATTEST_COMMITMENT: &str = "attestation-commitment-210";
const ATTEST_NONCE: &str = "attestation-nonce-210";
const GOV_PROOF_DIGEST: &str = "gov-proof-digest-210";
const NOW: u64 = 1_700_000_000;
const FRESH: u64 = 1_699_999_900;
const EXPIRES: u64 = 1_700_001_000;
const ISSUED: u64 = 1_699_999_950;
const WINDOW_SINCE: u64 = 1_699_999_000;
const WINDOW_UNTIL: u64 = 1_700_000_500;

// ---------------------------------------------------------------------------
// Fixture builders — mirror the Run 207/208 source/test corpus.
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

    /// Drive the chosen per-surface Run 209 preflight wrapper with the
    /// resolved custody-attestation policy and a loaded carrier. This is the
    /// chain Run 210 proves: CLI/env selector -> resolved
    /// CustodyAttestationPolicy -> Run 209 preflight wrapper -> Run 207
    /// routing helper -> Run 205 verifier / Run 188 boundary.
    fn preflight(
        &self,
        surface: Surface,
        custody_policy: AuthorityCustodyPolicy,
        attestation_policy: CustodyAttestationPolicy,
        loaded: &CustodyAttestationLoadStatus,
    ) -> CustodyAttestationPayloadCarryingDecisionOutcome {
        let f = surface_wrapper(surface);
        f(
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
            loaded,
        )
    }
}

// ---------------------------------------------------------------------------
// Per-surface preflight dispatch — one of the seven Run 209 preflight
// wrappers that inject the resolved custody-attestation policy into the Run
// 207 routing helpers.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Surface {
    ReloadCheck,
    ReloadApply,
    StartupP2p,
    Sighup,
    LocalPeerCandidate,
    LiveInbound0x05,
    PeerDrivenDrain,
}

const ALL_SURFACES: [Surface; 7] = [
    Surface::ReloadCheck,
    Surface::ReloadApply,
    Surface::StartupP2p,
    Surface::Sighup,
    Surface::LocalPeerCandidate,
    Surface::LiveInbound0x05,
    Surface::PeerDrivenDrain,
];

fn surface_name(s: Surface) -> &'static str {
    match s {
        Surface::ReloadCheck => "reload_check",
        Surface::ReloadApply => "reload_apply",
        Surface::StartupP2p => "startup_p2p_trust_bundle",
        Surface::Sighup => "sighup",
        Surface::LocalPeerCandidate => "local_peer_candidate_check",
        Surface::LiveInbound0x05 => "live_inbound_0x05",
        Surface::PeerDrivenDrain => "peer_driven_drain",
    }
}

type PreflightFn = fn(
    &AuthorityCustodyAttestation,
    Option<&PersistentAuthorityStateRecordVersioned>,
    &PersistentAuthorityStateRecordV2,
    &AuthorityTrustDomain,
    GovernanceAuthorityClass,
    LocalLifecycleAction,
    &str,
    u64,
    Option<&str>,
    AuthorityCustodyPolicy,
    CustodyAttestationPolicy,
    u64,
    &CustodyAttestationLoadStatus,
) -> CustodyAttestationPayloadCarryingDecisionOutcome;

fn surface_wrapper(s: Surface) -> PreflightFn {
    match s {
        Surface::ReloadCheck => preflight_v2_marker_custody_attestation_for_reload_check,
        Surface::ReloadApply => preflight_v2_marker_custody_attestation_for_reload_apply,
        Surface::StartupP2p => {
            preflight_v2_marker_custody_attestation_for_startup_p2p_trust_bundle
        }
        Surface::Sighup => preflight_v2_marker_custody_attestation_for_sighup,
        Surface::LocalPeerCandidate => {
            preflight_v2_marker_custody_attestation_for_local_peer_candidate_check
        }
        Surface::LiveInbound0x05 => preflight_v2_marker_custody_attestation_for_live_inbound_0x05,
        Surface::PeerDrivenDrain => preflight_v2_marker_custody_attestation_for_peer_driven_drain,
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
        Table {
            name,
            rows: String::new(),
            expected: String::new(),
            actual: String::new(),
            pass: 0,
            fail: 0,
        }
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
// Env serialization for the selector-resolution table. The helper is a
// single-threaded process; this RAII guard mutates and restores the hidden
// selector env var around each resolver call so the resolution table is
// deterministic regardless of the ambient environment.
// ---------------------------------------------------------------------------

struct EnvGuard {
    prior: Option<String>,
}

impl EnvGuard {
    fn set(value: Option<&str>) -> Self {
        let prior = std::env::var(QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY_ENV).ok();
        match value {
            Some(v) => std::env::set_var(QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY_ENV, v),
            None => std::env::remove_var(QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY_ENV),
        }
        EnvGuard { prior }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.prior.take() {
            Some(v) => std::env::set_var(QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY_ENV, v),
            None => std::env::remove_var(QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY_ENV),
        }
    }
}

// ---------------------------------------------------------------------------
// Table 1 — selector resolution (A1..A3, A11, R1..R3). Exercises the Run 209
// resolver `custody_attestation_policy_from_cli_or_env`,
// `custody_attestation_policy_env_selector`, and
// `custody_attestation_policy_from_selector` in release mode.
// ---------------------------------------------------------------------------

fn run_selector_table(out: &Path) -> (u64, u64) {
    let mut t = Table::new("selector");

    let canonical: &[(&str, CustodyAttestationPolicy)] = &[
        (CUSTODY_ATTESTATION_POLICY_TAG_DISABLED, CustodyAttestationPolicy::Disabled),
        (
            CUSTODY_ATTESTATION_POLICY_TAG_FIXTURE_ATTESTATION_ALLOWED,
            CustodyAttestationPolicy::FixtureAttestationAllowed,
        ),
        (
            CUSTODY_ATTESTATION_POLICY_TAG_REMOTE_SIGNER_ATTESTATION_REQUIRED,
            CustodyAttestationPolicy::RemoteSignerAttestationRequired,
        ),
        (
            CUSTODY_ATTESTATION_POLICY_TAG_KMS_ATTESTATION_REQUIRED,
            CustodyAttestationPolicy::KmsAttestationRequired,
        ),
        (
            CUSTODY_ATTESTATION_POLICY_TAG_HSM_ATTESTATION_REQUIRED,
            CustodyAttestationPolicy::HsmAttestationRequired,
        ),
        (
            CUSTODY_ATTESTATION_POLICY_TAG_PRODUCTION_ATTESTATION_REQUIRED,
            CustodyAttestationPolicy::ProductionAttestationRequired,
        ),
        (
            CUSTODY_ATTESTATION_POLICY_TAG_MAINNET_PRODUCTION_ATTESTATION_REQUIRED,
            CustodyAttestationPolicy::MainnetProductionAttestationRequired,
        ),
    ];

    // A1 — default (no CLI, no env) resolves to Disabled (bit-for-bit).
    {
        let _g = EnvGuard::set(None);
        let resolved = custody_attestation_policy_from_cli_or_env(None);
        t.assert_true(
            "A1.default-absent-is-disabled",
            resolved == Ok(CustodyAttestationPolicy::Disabled),
            &format!("resolved={resolved:?}"),
        );
    }

    // A2 — CLI selector resolves each canonical tag (env unset).
    {
        let _g = EnvGuard::set(None);
        for (tag, expected) in canonical {
            let resolved = custody_attestation_policy_from_cli_or_env(Some(tag));
            t.assert_true(
                &format!("A2.cli-{tag}"),
                resolved == Ok(*expected),
                &format!("cli={tag:?} resolved={resolved:?}"),
            );
        }
    }

    // A3 — env selector resolves each canonical tag (CLI absent).
    {
        for (tag, expected) in canonical {
            let _g = EnvGuard::set(Some(tag));
            let via_env = custody_attestation_policy_env_selector();
            let resolved = custody_attestation_policy_from_cli_or_env(None);
            t.assert_true(
                &format!("A3.env-{tag}"),
                via_env == Ok(Some(*expected)) && resolved == Ok(*expected),
                &format!("env={tag:?} via_env={via_env:?} resolved={resolved:?}"),
            );
        }
    }

    // A11 — CLI-over-env precedence is deterministic: env fixture, CLI
    // disabled -> Disabled (and the reverse direction).
    {
        let _g = EnvGuard::set(Some(CUSTODY_ATTESTATION_POLICY_TAG_FIXTURE_ATTESTATION_ALLOWED));
        let resolved =
            custody_attestation_policy_from_cli_or_env(Some(CUSTODY_ATTESTATION_POLICY_TAG_DISABLED));
        t.check(
            "A11.cli-over-env",
            "disabled",
            resolved.as_ref().map(|p| p.tag()).unwrap_or("err"),
        );
    }
    {
        let _g = EnvGuard::set(Some(CUSTODY_ATTESTATION_POLICY_TAG_DISABLED));
        let resolved = custody_attestation_policy_from_cli_or_env(Some(
            CUSTODY_ATTESTATION_POLICY_TAG_FIXTURE_ATTESTATION_ALLOWED,
        ));
        t.check(
            "A11.cli-over-env-reverse",
            "fixture-attestation-allowed",
            resolved.as_ref().map(|p| p.tag()).unwrap_or("err"),
        );
    }

    // R1 — invalid CLI selector value fails closed with a typed error.
    {
        let _g = EnvGuard::set(None);
        let err = custody_attestation_policy_from_cli_or_env(Some("totally-bogus"));
        t.assert_true(
            "R1.invalid-cli-rejected",
            matches!(
                err,
                Err(CustodyAttestationPolicySelectorParseError::UnknownValue { .. })
            ),
            &format!("err={err:?}"),
        );
        let empty = custody_attestation_policy_from_cli_or_env(Some("   "));
        t.assert_true(
            "R1.empty-cli-rejected",
            empty == Err(CustodyAttestationPolicySelectorParseError::Empty),
            &format!("empty={empty:?}"),
        );
    }

    // R2 — invalid env selector value fails closed with a typed error.
    {
        let _g = EnvGuard::set(Some("nope-not-a-policy"));
        let via_env = custody_attestation_policy_env_selector();
        let resolved = custody_attestation_policy_from_cli_or_env(None);
        t.assert_true(
            "R2.invalid-env-rejected",
            matches!(
                via_env,
                Err(CustodyAttestationPolicySelectorParseError::UnknownValue { .. })
            ) && resolved.is_err(),
            &format!("via_env={via_env:?} resolved={resolved:?}"),
        );
    }

    // R3 — an unrelated env var does not enable the custody-attestation policy.
    {
        let _g = EnvGuard::set(None);
        std::env::set_var("QBIND_SOME_UNRELATED_FLAG_210", "fixture-attestation-allowed");
        let resolved = custody_attestation_policy_from_cli_or_env(None);
        std::env::remove_var("QBIND_SOME_UNRELATED_FLAG_210");
        t.assert_true(
            "R3.unrelated-env-stays-disabled",
            resolved == Ok(CustodyAttestationPolicy::Disabled),
            &format!("resolved={resolved:?}"),
        );
    }

    // Case-insensitive / trimmed matching is honored by the pure parser.
    {
        let resolved = custody_attestation_policy_from_selector("  FIXTURE-ATTESTATION-ALLOWED  ");
        t.assert_true(
            "parser.case-insensitive-trim",
            resolved == Ok(CustodyAttestationPolicy::FixtureAttestationAllowed),
            &format!("resolved={resolved:?}"),
        );
    }

    t.finish(out)
}

// ---------------------------------------------------------------------------
// Table 2 — accepted / compatible cases driven through the seven Run 209
// preflight wrappers (A4..A15).
// ---------------------------------------------------------------------------

fn run_accepted_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("accepted");

    // A4 — CLI fixture-attestation-allowed resolves and accepts DevNet
    // fixture attestation through every preflight surface that is not the
    // MainNet-refused peer-driven drain.
    {
        let policy = custody_attestation_policy_from_cli_or_env(Some(
            CUSTODY_ATTESTATION_POLICY_TAG_FIXTURE_ATTESTATION_ALLOWED,
        ))
        .expect("fixture policy resolves");
        let s = accepted_scenario(Env::Devnet);
        let loaded = s.loaded();
        for surface in ALL_SURFACES {
            let outcome = s.preflight(surface, AuthorityCustodyPolicy::FixtureOnly, policy, &loaded);
            t.check(
                &format!("A4.{}", surface_name(surface)),
                "callsite:accept:Accepted",
                &decision_tag(&outcome),
            );
        }
    }

    // A5 — env fixture-attestation-allowed resolves and accepts TestNet
    // fixture attestation through the reload-check preflight wrapper.
    {
        let _g = EnvGuard::set(Some(CUSTODY_ATTESTATION_POLICY_TAG_FIXTURE_ATTESTATION_ALLOWED));
        let policy = custody_attestation_policy_from_cli_or_env(None).expect("env fixture resolves");
        let s = accepted_scenario(Env::Testnet);
        let loaded = loaded_via_json(&s.parts());
        let outcome =
            s.preflight(Surface::ReloadCheck, AuthorityCustodyPolicy::FixtureOnly, policy, &loaded);
        t.check("A5.env-testnet-fixture", "callsite:accept:Accepted", &decision_tag(&outcome));
    }

    // A6..A9 — required policies reach the typed unavailable outcome (no real
    // verifier exists). Each carries a matching production-class attestation
    // and resolves the policy from the CLI selector.
    let required_cases: &[(&str, &str, CustodyAttestationClass)] = &[
        (
            "A6.remote-signer",
            CUSTODY_ATTESTATION_POLICY_TAG_REMOTE_SIGNER_ATTESTATION_REQUIRED,
            CustodyAttestationClass::RemoteSignerAttestation,
        ),
        (
            "A7.kms",
            CUSTODY_ATTESTATION_POLICY_TAG_KMS_ATTESTATION_REQUIRED,
            CustodyAttestationClass::KmsAttestation,
        ),
        (
            "A8.hsm",
            CUSTODY_ATTESTATION_POLICY_TAG_HSM_ATTESTATION_REQUIRED,
            CustodyAttestationClass::HsmAttestation,
        ),
        (
            "A9.production",
            CUSTODY_ATTESTATION_POLICY_TAG_PRODUCTION_ATTESTATION_REQUIRED,
            CustodyAttestationClass::ProductionAttestationUnavailable,
        ),
    ];
    for (id, tag, class) in required_cases {
        let policy = custody_attestation_policy_from_cli_or_env(Some(tag)).expect("policy resolves");
        let mut s = accepted_scenario(Env::Devnet);
        s.evidence.attestation_class = *class;
        let loaded = s.loaded();
        let outcome =
            s.preflight(Surface::ReloadCheck, AuthorityCustodyPolicy::FixtureOnly, policy, &loaded);
        let unavailable = routed_attestation(&outcome).map(|o| o.is_unavailable()).unwrap_or(false);
        t.assert_true(id, !outcome.is_accept() && unavailable, "");
    }

    // A10 — env mainnet-production-attestation-required resolves and reaches
    // the typed MainNet production unavailable / refusal outcome.
    {
        let _g =
            EnvGuard::set(Some(CUSTODY_ATTESTATION_POLICY_TAG_MAINNET_PRODUCTION_ATTESTATION_REQUIRED));
        let policy = custody_attestation_policy_from_cli_or_env(None).expect("env mainnet resolves");
        let mut s = accepted_scenario(Env::Devnet);
        s.evidence.attestation_class = CustodyAttestationClass::ProductionAttestationUnavailable;
        let loaded = s.loaded();
        let outcome =
            s.preflight(Surface::ReloadCheck, AuthorityCustodyPolicy::FixtureOnly, policy, &loaded);
        let tag = routed_attestation(&outcome).map(attestation_tag).unwrap_or_default();
        t.check("A10.env-mainnet-production", "reject:MainNetProductionAttestationUnavailable", &tag);
    }

    // A12 — no-attestation payload remains compatible under default Disabled
    // through the reload-check preflight wrapper (bypass).
    {
        let policy = custody_attestation_policy_from_cli_or_env(Some(
            CUSTODY_ATTESTATION_POLICY_TAG_DISABLED,
        ))
        .expect("disabled resolves");
        let s = accepted_scenario(Env::Devnet);
        let outcome = s.preflight(
            Surface::ReloadCheck,
            AuthorityCustodyPolicy::FixtureOnly,
            policy,
            &CustodyAttestationLoadStatus::Absent,
        );
        t.check("A12.no-attestation-disabled", "bypass:NoCustodyAttestationSupplied", &decision_tag(&outcome));
        t.assert_true("A12.bypassed", outcome.is_bypassed() && !outcome.is_reject(), "");
    }

    // A13 — GenesisBound / EmergencyCouncil / OnChainGovernance proof
    // behavior unchanged when custody-attestation policy is Disabled.
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
        t.assert_true(&format!("A13.{gov:?}"), outcome.is_bypassed(), "");
    }

    // A14 — Run 193 custody-policy selector behavior remains compatible: the
    // custody policy and the attestation policy are independent selectors.
    {
        let policy = custody_attestation_policy_from_cli_or_env(Some(
            CUSTODY_ATTESTATION_POLICY_TAG_FIXTURE_ATTESTATION_ALLOWED,
        ))
        .expect("fixture resolves");
        let s = accepted_scenario(Env::Devnet);
        let loaded = s.loaded();
        let outcome =
            s.preflight(Surface::ReloadCheck, AuthorityCustodyPolicy::DevnetLocalAllowed, policy, &loaded);
        t.check("A14.custody-policy-compat", "callsite:accept:Accepted", &decision_tag(&outcome));
    }

    // A15 — Run 199 RemoteSigner-policy selector behavior remains compatible:
    // a fixture-remote-signer custody class accepts under fixture attestation.
    {
        let policy = custody_attestation_policy_from_cli_or_env(Some(
            CUSTODY_ATTESTATION_POLICY_TAG_FIXTURE_ATTESTATION_ALLOWED,
        ))
        .expect("fixture resolves");
        let mut s = accepted_scenario(Env::Devnet);
        s.evidence.custody_backend_kind = Some("fixture-remote-signer".to_string());
        s.evidence.custody_class = AuthorityCustodyClass::RemoteSigner;
        s.input.expected_custody_class = AuthorityCustodyClass::RemoteSigner;
        let loaded = loaded_via_json(&s.parts());
        let outcome =
            s.preflight(Surface::ReloadCheck, AuthorityCustodyPolicy::FixtureOnly, policy, &loaded);
        t.check("A15.remote-signer-policy-compat", "callsite:accept:Accepted", &decision_tag(&outcome));
    }

    t.finish(out)
}

// ---------------------------------------------------------------------------
// Table 3 — rejection cases R4..R40 driven through the Run 209 preflight
// wrappers and the Run 207 routing helpers / Run 205 verifier.
// ---------------------------------------------------------------------------

/// Mutate the carried evidence/input via the closure, route through the
/// reload-check preflight wrapper under fixture custody + fixture attestation
/// policy, and return the routed inner attestation outcome (panics if not a
/// verifier reject).
fn assert_attestation_rejected(mutate: impl FnOnce(&mut Scenario)) -> CustodyAttestationOutcome {
    let mut s = accepted_scenario(TrustBundleEnvironment::Devnet);
    mutate(&mut s);
    let loaded = s.loaded();
    let outcome = s.preflight(
        Surface::ReloadCheck,
        AuthorityCustodyPolicy::FixtureOnly,
        CustodyAttestationPolicy::FixtureAttestationAllowed,
        &loaded,
    );
    routed_attestation(&outcome)
        .cloned()
        .unwrap_or_else(|| panic!("expected AttestationRejected, got {outcome:?}"))
}

fn run_rejection_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("rejection");

    // R4 — no-attestation payload rejected under FixtureAttestationAllowed.
    {
        let s = accepted_scenario(Env::Devnet);
        let outcome = s.preflight(
            Surface::ReloadCheck,
            AuthorityCustodyPolicy::FixtureOnly,
            CustodyAttestationPolicy::FixtureAttestationAllowed,
            &CustodyAttestationLoadStatus::Absent,
        );
        t.check("R4", "reject:CustodyAttestationRequiredButAbsent", &decision_tag(&outcome));
        t.assert_true("R4.flags", outcome.is_required_but_absent() && outcome.is_reject(), "");
    }

    // R5 — no-attestation payload rejected under ProductionAttestationRequired.
    {
        let s = accepted_scenario(Env::Devnet);
        let outcome = s.preflight(
            Surface::ReloadCheck,
            AuthorityCustodyPolicy::FixtureOnly,
            CustodyAttestationPolicy::ProductionAttestationRequired,
            &CustodyAttestationLoadStatus::Absent,
        );
        t.check("R5", "reject:CustodyAttestationRequiredButAbsent", &decision_tag(&outcome));
    }

    // R6 — fixture attestation rejected under ProductionAttestationRequired.
    {
        let s = accepted_scenario(Env::Devnet);
        let loaded = s.loaded();
        let outcome = s.preflight(
            Surface::ReloadCheck,
            AuthorityCustodyPolicy::FixtureOnly,
            CustodyAttestationPolicy::ProductionAttestationRequired,
            &loaded,
        );
        let tag = routed_attestation(&outcome).map(attestation_tag).unwrap_or_default();
        t.check("R6", "reject:FixtureRejectedProductionRequired", &tag);
    }

    // R7 — fixture attestation rejected under MainnetProductionAttestationRequired.
    {
        let s = accepted_scenario(Env::Devnet);
        let loaded = s.loaded();
        let outcome = s.preflight(
            Surface::ReloadCheck,
            AuthorityCustodyPolicy::FixtureOnly,
            CustodyAttestationPolicy::MainnetProductionAttestationRequired,
            &loaded,
        );
        let tag = routed_attestation(&outcome).map(attestation_tag).unwrap_or_default();
        t.check("R7", "reject:FixtureRejectedMainnetProductionRequired", &tag);
    }

    // R8–R14 — production-class attestations rejected as unavailable.
    let unavailable_cases: &[(&str, &str, CustodyAttestationClass, CustodyAttestationPolicy)] = &[
        ("R8", "remote-signer", CustodyAttestationClass::RemoteSignerAttestation, CustodyAttestationPolicy::FixtureAttestationAllowed),
        ("R9", "kms", CustodyAttestationClass::KmsAttestation, CustodyAttestationPolicy::FixtureAttestationAllowed),
        ("R10", "hsm", CustodyAttestationClass::HsmAttestation, CustodyAttestationPolicy::FixtureAttestationAllowed),
        ("R11", "cloud-kms", CustodyAttestationClass::CloudKmsAttestationUnavailable, CustodyAttestationPolicy::FixtureAttestationAllowed),
        ("R12", "pkcs11", CustodyAttestationClass::Pkcs11HsmAttestationUnavailable, CustodyAttestationPolicy::FixtureAttestationAllowed),
        ("R13", "production", CustodyAttestationClass::ProductionAttestationUnavailable, CustodyAttestationPolicy::ProductionAttestationRequired),
        ("R14", "mainnet-production", CustodyAttestationClass::ProductionAttestationUnavailable, CustodyAttestationPolicy::MainnetProductionAttestationRequired),
    ];
    for (id, _name, class, policy) in unavailable_cases {
        let mut s = accepted_scenario(Env::Devnet);
        s.evidence.attestation_class = *class;
        let loaded = s.loaded();
        let outcome =
            s.preflight(Surface::ReloadCheck, AuthorityCustodyPolicy::FixtureOnly, *policy, &loaded);
        let unavailable = routed_attestation(&outcome).map(|o| o.is_unavailable()).unwrap_or(false);
        t.assert_true(id, !outcome.is_accept() && unavailable, "");
    }

    // R15 — malformed custody-attestation material rejected (empty required field).
    {
        let s = accepted_scenario(Env::Devnet);
        let mut wire = CustodyAttestationPayloadWire::from_parts(&s.evidence, &s.input);
        wire.evidence.candidate_digest = String::new();
        let value = serde_json::json!({
            CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD: serde_json::to_value(&wire).unwrap()
        });
        let loaded = parse_optional_custody_attestation_sibling_from_json_value(&value);
        t.assert_true("R15.malformed", loaded.is_malformed(), "");
        let outcome = s.preflight(
            Surface::ReloadCheck,
            AuthorityCustodyPolicy::FixtureOnly,
            CustodyAttestationPolicy::FixtureAttestationAllowed,
            &loaded,
        );
        t.assert_true("R15", outcome.is_malformed_payload() && outcome.is_reject(), "");
    }

    // R16–R31 — wrong-binding rejections route through the Run 205 verifier.
    t.check("R16", "reject:WrongEnvironment", &attestation_tag(&assert_attestation_rejected(|s| {
        s.evidence.environment = TrustBundleEnvironment::Testnet;
    })));
    t.check("R17", "reject:WrongChain", &attestation_tag(&assert_attestation_rejected(|s| {
        s.evidence.chain_id = "deadbeef".to_string();
        s.input.expected_chain_id = "deadbeef".to_string();
    })));
    t.check("R18", "reject:WrongGenesis", &attestation_tag(&assert_attestation_rejected(|s| {
        s.evidence.genesis_hash = "ff".repeat(32);
        s.input.expected_genesis_hash = "ff".repeat(32);
    })));
    t.check("R19", "reject:WrongAuthorityRoot", &attestation_tag(&assert_attestation_rejected(|s| {
        s.evidence.authority_root_fingerprint = "9".repeat(40);
        s.input.expected_authority_root_fingerprint = "9".repeat(40);
    })));
    t.check("R20", "reject:WrongSigningKeyFingerprint", &attestation_tag(&assert_attestation_rejected(|s| {
        s.evidence.bundle_signing_key_fingerprint = "0".repeat(40);
    })));
    t.check("R21", "reject:WrongCustodyClass", &attestation_tag(&assert_attestation_rejected(|s| {
        s.evidence.custody_class = AuthorityCustodyClass::Hsm;
    })));
    t.check("R22", "reject:WrongBackendProviderSignerId", &attestation_tag(&assert_attestation_rejected(|s| {
        s.evidence.backend_provider_signer_id = "other-provider".to_string();
    })));
    t.check("R23", "reject:WrongKeyId", &attestation_tag(&assert_attestation_rejected(|s| {
        s.evidence.custody_key_id = "other-key".to_string();
    })));
    t.check("R24", "reject:WrongSuite", &attestation_tag(&assert_attestation_rejected(|s| {
        s.evidence.suite_id = 99;
    })));
    t.check("R25", "reject:WrongLifecycleAction", &attestation_tag(&assert_attestation_rejected(|s| {
        s.evidence.lifecycle_action = LocalLifecycleAction::Revoke;
    })));
    t.check("R26", "reject:WrongCandidateDigest", &attestation_tag(&assert_attestation_rejected(|s| {
        s.evidence.candidate_digest = "3".repeat(64);
    })));
    t.check("R27", "reject:WrongAuthorityDomainSequence", &attestation_tag(&assert_attestation_rejected(|s| {
        s.evidence.authority_domain_sequence = 9;
    })));
    t.check("R28", "reject:WrongGovernanceProofDigest", &attestation_tag(&assert_attestation_rejected(|s| {
        s.evidence.governance_proof_digest = Some("other-gov-proof".to_string());
    })));
    t.check("R29", "reject:WrongRequestDigest", &attestation_tag(&assert_attestation_rejected(|s| {
        s.evidence.request_digest = Some("other-request".to_string());
    })));
    t.check("R30", "reject:WrongResponseDigest", &attestation_tag(&assert_attestation_rejected(|s| {
        s.evidence.response_digest = Some("other-response".to_string());
    })));
    t.check("R31", "reject:WrongTranscriptDigest", &attestation_tag(&assert_attestation_rejected(|s| {
        s.evidence.transcript_digest = Some("other-transcript".to_string());
    })));

    // R32 — stale / replayed attestation rejected.
    t.check("R32", "reject:StaleOrReplayedAttestation", &attestation_tag(&assert_attestation_rejected(|s| {
        s.evidence.attestation_nonce = "stale-nonce".to_string();
    })));

    // R33 — expired attestation rejected.
    t.check("R33", "reject:ExpiredAttestation", &attestation_tag(&assert_attestation_rejected(|s| {
        s.evidence.freshness_unix = Some(1);
        s.evidence.expires_at_unix = Some(2);
    })));

    // R34 — invalid attestation commitment rejected.
    t.check("R34", "reject:InvalidAttestationCommitment", &attestation_tag(&assert_attestation_rejected(|s| {
        s.evidence.attestation_commitment =
            CUSTODY_ATTESTATION_INVALID_COMMITMENT_SENTINEL.to_string();
    })));

    // R35 — local operator cannot satisfy production attestation.
    {
        let s = accepted_scenario(Env::Devnet);
        let loaded = s.loaded();
        let outcome = s.preflight(
            Surface::ReloadCheck,
            AuthorityCustodyPolicy::FixtureOnly,
            CustodyAttestationPolicy::ProductionAttestationRequired,
            &loaded,
        );
        t.assert_true("R35", !outcome.is_accept(), "");
    }

    // R36 — peer majority / gossip count cannot satisfy production attestation.
    {
        let mut s = accepted_scenario(Env::Devnet);
        s.evidence.attestation_class = CustodyAttestationClass::ProductionAttestationUnavailable;
        let loaded = s.loaded();
        let outcome = s.preflight(
            Surface::PeerDrivenDrain,
            AuthorityCustodyPolicy::FixtureOnly,
            CustodyAttestationPolicy::ProductionAttestationRequired,
            &loaded,
        );
        t.assert_true("R36", !outcome.is_accept(), "");
    }

    // R37 — validation-only rejection is pure (stable repeat results) and
    //       writes no marker / no sequence (preflight wrappers are pure).
    {
        let s = accepted_scenario(Env::Devnet);
        let loaded = s.loaded();
        let first = s.preflight(
            Surface::ReloadCheck,
            AuthorityCustodyPolicy::FixtureOnly,
            CustodyAttestationPolicy::ProductionAttestationRequired,
            &loaded,
        );
        let again = s.preflight(
            Surface::ReloadCheck,
            AuthorityCustodyPolicy::FixtureOnly,
            CustodyAttestationPolicy::ProductionAttestationRequired,
            &loaded,
        );
        t.assert_true("R37", first == again && !first.is_accept(), "");
    }

    // R38 — mutating-surface rejection produces a typed reject and no apply:
    //       custody valid but attestation invalid rejected through reload-apply.
    {
        let mut s = accepted_scenario(Env::Devnet);
        s.evidence.attestation_commitment =
            CUSTODY_ATTESTATION_INVALID_COMMITMENT_SENTINEL.to_string();
        let loaded = s.loaded();
        let outcome = s.preflight(
            Surface::ReloadApply,
            AuthorityCustodyPolicy::FixtureOnly,
            CustodyAttestationPolicy::FixtureAttestationAllowed,
            &loaded,
        );
        t.assert_true("R38", !outcome.is_accept() && !outcome.is_bypassed(), "");
    }

    // R39 — invalid live inbound 0x05 custody-attestation candidate is not
    //       propagated / staged / applied.
    {
        let s = accepted_scenario(Env::Devnet);
        let mut wire = CustodyAttestationPayloadWire::from_parts(&s.evidence, &s.input);
        wire.evidence.attestation_commitment = String::new();
        let value = serde_json::json!({
            CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD: serde_json::to_value(&wire).unwrap()
        });
        let loaded = parse_optional_custody_attestation_sibling_from_json_value(&value);
        let outcome = s.preflight(
            Surface::LiveInbound0x05,
            AuthorityCustodyPolicy::FixtureOnly,
            CustodyAttestationPolicy::FixtureAttestationAllowed,
            &loaded,
        );
        t.assert_true("R39", outcome.is_malformed_payload() && outcome.is_reject(), "");
    }

    // R40 — MainNet peer-driven apply remains refused even with
    //       MainnetProductionAttestationRequired and fixture attestation.
    {
        let s = accepted_scenario(Env::Mainnet);
        let loaded = s.loaded();
        let outcome = s.preflight(
            Surface::PeerDrivenDrain,
            AuthorityCustodyPolicy::FixtureOnly,
            CustodyAttestationPolicy::MainnetProductionAttestationRequired,
            &loaded,
        );
        t.check("R40", "reject:MainNetPeerDrivenApplyRefused", &decision_tag(&outcome));
        t.assert_true(
            "R40.helper",
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
// Table 4 — loader compatibility (legacy / carry / malformed sidecars).
// ---------------------------------------------------------------------------

/// Mint a real signed v2 ratification sidecar JSON value with an optional
/// `custody_attestation` sibling, mirroring the Run 207/208 source/test helper.
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
        let path = PathBuf::from("/dev/null/run-210-legacy.json");
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
        let path = PathBuf::from("/dev/null/run-210-carry.json");
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
        let path = PathBuf::from("/dev/null/run-210-malformed.json");
        let loaded = load_v2_ratification_sidecar_with_custody_attestation_from_bytes(&bytes, &path)
            .expect("v2 ratification still parses");
        t.assert_true("L3", loaded.custody_attestation.is_malformed(), "");
    }

    // L4 — canonical sibling field name + schema version.
    t.check("L4.field", "custody_attestation", CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD);
    t.check("L4.version", "1", &CUSTODY_ATTESTATION_PAYLOAD_WIRE_SCHEMA_VERSION.to_string());

    // L5 — unsupported future schema version rejected as Malformed.
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
        t.assert_true("L5", is_unknown_version, "");
    }

    // L6 — absent sibling when field missing or explicitly null.
    {
        let missing = serde_json::json!({ "schema_version": 2 });
        let null = serde_json::json!({ CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD: null });
        t.assert_true(
            "L6",
            parse_optional_custody_attestation_sibling_from_json_value(&missing).is_absent()
                && parse_optional_custody_attestation_sibling_from_json_value(&null).is_absent(),
            "",
        );
    }

    t.finish(out)
}

// ---------------------------------------------------------------------------
// Table 5 — determinism + per-surface reachability + MainNet refusal.
// ---------------------------------------------------------------------------

fn run_reachability_table(out: &Path) -> (u64, u64) {
    use TrustBundleEnvironment as Env;
    let mut t = Table::new("reachability");

    // Determinism — repeated wire round-trips yield byte-identical digests.
    let s = accepted_scenario(Env::Devnet);
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

    // Each of the seven Run 209 preflight wrappers reaches the Run 205 verifier
    // and accepts the fixture carrier on DevNet (peer-driven drain only
    // refuses on MainNet, so it accepts on DevNet too).
    let loaded = s.loaded();
    for surface in ALL_SURFACES {
        let outcome = s.preflight(
            surface,
            AuthorityCustodyPolicy::FixtureOnly,
            CustodyAttestationPolicy::FixtureAttestationAllowed,
            &loaded,
        );
        t.assert_true(&format!("S.{}", surface_name(surface)), outcome.is_accept(), "");
    }

    // MainNet refusal helper.
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

    // The peer-driven drain surface refuses MainNet through the Run 209
    // preflight wrapper even under MainnetProductionAttestationRequired.
    {
        let ms = accepted_scenario(Env::Mainnet);
        let mloaded = ms.loaded();
        let outcome = ms.preflight(
            Surface::PeerDrivenDrain,
            AuthorityCustodyPolicy::FixtureOnly,
            CustodyAttestationPolicy::MainnetProductionAttestationRequired,
            &mloaded,
        );
        t.assert_true("M4.drain_mainnet_refused", outcome.is_mainnet_peer_driven_apply_refused(), "");
    }

    t.finish(out)
}

// ---------------------------------------------------------------------------
// Fixture dump — canonical carrier sidecars + digests + selector tags for the
// archive.
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

    // Canonical selector tags + env-var name for the archive.
    let mut tags = String::new();
    tags.push_str(&format!("env_var\t{QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY_ENV}\n"));
    tags.push_str("cli_flag\t--p2p-trust-bundle-custody-attestation-policy\n");
    for p in [
        CustodyAttestationPolicy::Disabled,
        CustodyAttestationPolicy::FixtureAttestationAllowed,
        CustodyAttestationPolicy::RemoteSignerAttestationRequired,
        CustodyAttestationPolicy::KmsAttestationRequired,
        CustodyAttestationPolicy::HsmAttestationRequired,
        CustodyAttestationPolicy::ProductionAttestationRequired,
        CustodyAttestationPolicy::MainnetProductionAttestationRequired,
    ] {
        tags.push_str(&format!("policy\t{}\t{:?}\n", p.tag(), p));
    }
    write_file(&dir.join("selector_tags.txt"), &tags);
}

fn main() {
    let mut args = env::args().skip(1);
    let out_dir = match args.next() {
        Some(a) => PathBuf::from(a),
        None => {
            eprintln!(
                "usage: run_210_custody_attestation_policy_release_binary_helper <OUT_DIR>"
            );
            std::process::exit(2);
        }
    };
    fs::create_dir_all(&out_dir).unwrap_or_else(|e| panic!("create out dir {out_dir:?}: {e}"));

    let tables: &[(&str, fn(&Path) -> (u64, u64))] = &[
        ("selector", run_selector_table),
        ("accepted", run_accepted_table),
        ("rejection", run_rejection_table),
        ("loader", run_loader_table),
        ("reachability", run_reachability_table),
    ];

    let mut total_pass = 0u64;
    let mut total_fail = 0u64;
    let mut summary = String::new();
    summary.push_str("run_210_custody_attestation_policy_release_binary_helper\n");
    summary.push_str(
        "scope: Run 209 hidden custody-attestation policy selector + seven production preflight wrappers over the Run 207 routing helpers, Run 205 verifier and Run 188 custody boundary (release binary)\n",
    );
    summary.push_str(
        "note: fixture-only; hidden CLI/env selector, disabled by default; no real cloud-KMS/PKCS#11/HSM-vendor/RemoteSigner attestation verifier; no real KMS/HSM/RemoteSigner backend; no live trust mutation; no P2P socket; production attestation routes to verifier and fails closed; MainNet peer-driven apply remains refused\n\n",
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
