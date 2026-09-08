//! Run 199 — release-built helper that exercises the Run 198 hidden
//! **RemoteSigner policy selector**
//! ([`qbind_node::pqc_remote_signer_policy_surface`]) **in release mode**,
//! routing the resolved [`RemoteSignerPolicy`] through the seven Run 198
//! per-surface preflight wrappers
//! ([`preflight_v2_marker_remote_signer_for_*`]) and therefore through the
//! Run 196 RemoteSigner attestation payload-carrying helpers
//! ([`qbind_node::pqc_remote_signer_payload_carrying`]) layered over the
//! Run 194 RemoteSigner boundary
//! ([`qbind_node::pqc_remote_authority_signer`]).
//!
//! Per `task/RUN_199_TASK.txt`, Run 199 is the release-binary evidence run
//! for the Run 198 source/test RemoteSigner policy selector. This helper is
//! fixture-only tooling and:
//!
//! * does NOT modify any production runtime code, CLI flag, env var, wire /
//!   marker / sequence / trust-bundle / peer-candidate-envelope schema
//!   beyond what Runs 070, 130–198 already established;
//! * does NOT enable MainNet peer-driven apply on any surface;
//! * does NOT mutate any live trust state, write any marker, advance any
//!   sequence, swap any live trust, evict any session, or invoke Run 070 —
//!   every selector resolver and preflight wrapper exercised here is a pure
//!   function returning an owned typed outcome;
//! * does NOT open any P2P socket;
//! * does NOT implement any real RemoteSigner backend, networked signer
//!   service, real KMS, real HSM, cloud KMS, or PKCS#11 integration; a
//!   `Production` signer-mode response always reaches the boundary and
//!   returns the typed `RemoteSignerOutcome::ProductionRemoteSignerUnavailable`
//!   (or its MainNet variant) reject;
//! * never elevates the DevNet/TestNet fixture-loopback RemoteSigner into
//!   MainNet production custody (MainNet peer-driven apply always refuses at
//!   the typed boundary);
//! * exists alongside (and does NOT replace) the Run 198 source/test target
//!   `crates/qbind-node/tests/run_198_remote_signer_policy_selector_tests.rs`.
//!
//! The helper proves, in release mode through the production library
//! symbols:
//!
//! 1. default behaviour resolves to `RemoteSignerPolicy::Disabled`;
//! 2. the hidden CLI selector resolves;
//! 3. the env selector resolves;
//! 4. CLI-over-env precedence is deterministic;
//! 5. invalid selector values fail closed with typed parse errors;
//! 6. the resolved policy reaches all seven production preflight contexts;
//! 7. fixture loopback RemoteSigner material passes only where the selected
//!    policy allows;
//! 8. production RemoteSigner remains fail-closed as unavailable;
//! 9. MainNet peer-driven apply remains refused even with
//!    `MainnetProductionRemoteSignerRequired` and fixture loopback material;
//! 10. no real RemoteSigner/KMS/HSM/governance execution/validator-set
//!     rotation is claimed.
//!
//! Usage:
//! ```text
//! run_199_remote_signer_policy_release_binary_helper <OUT_DIR>
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
    peer_majority_cannot_satisfy_remote_signer, FixtureLoopbackRemoteSigner,
    LifecycleCustodyRemoteSignerOutcome, RemoteAuthoritySigner, RemoteSignerExpectations,
    RemoteSignerIdentity, RemoteSignerMode, RemoteSignerOutcome, RemoteSignerPolicy,
    RemoteSignerRequest, RemoteSignerResponse, REMOTE_SIGNER_INVALID_SIGNATURE_SENTINEL,
};
use qbind_node::pqc_remote_signer_payload_carrying::{
    callsite_context_for_remote_signer,
    load_v2_ratification_sidecar_with_remote_signer_attestation_from_bytes,
    mainnet_peer_driven_apply_remains_refused_under_remote_signer_payload_carrying,
    parse_optional_remote_signer_attestation_sibling_from_json_value,
    route_remote_signer_attestation_for_custody_class, validate_loaded_remote_signer,
    RemoteSignerAttestationParts, RemoteSignerAttestationWire, RemoteSignerCallsiteContext,
    RemoteSignerLoadStatus, RemoteSignerPayloadCarryingDecisionOutcome,
    REMOTE_SIGNER_ATTESTATION_PAYLOAD_SIBLING_FIELD,
};
use qbind_node::pqc_remote_signer_policy_surface::{
    preflight_v2_marker_remote_signer_for_live_inbound_0x05,
    preflight_v2_marker_remote_signer_for_local_peer_candidate_check,
    preflight_v2_marker_remote_signer_for_peer_driven_drain,
    preflight_v2_marker_remote_signer_for_reload_apply,
    preflight_v2_marker_remote_signer_for_reload_check,
    preflight_v2_marker_remote_signer_for_sighup,
    preflight_v2_marker_remote_signer_for_startup_p2p_trust_bundle,
    remote_signer_policy_env_selector, remote_signer_policy_from_cli_or_env,
    remote_signer_policy_from_selector, RemoteSignerPolicySelectorParseError,
    QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY_ENV,
};
use qbind_node::pqc_trust_bundle::TrustBundleEnvironment;

// ---------------------------------------------------------------------------
// Constants — kept structurally identical to the Run 196/198 source/test
// fixtures so the typed RemoteSigner payload-carrying semantics carry over
// end-to-end in release mode.
// ---------------------------------------------------------------------------

const KEY_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEY_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ROOT_FP: &str = "1111111111111111111111111111111111111111";
const OTHER_ROOT_FP: &str = "9999999999999999999999999999999999999999";
const CHAIN_ID: &str = "0000000000000001";
const OTHER_CHAIN: &str = "00000000000000ff";
const GENESIS_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER_GENESIS: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const DIGEST_2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const DIGEST_OTHER: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const PRIOR_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const OTHER_SIGNING_FP: &str = "cccccccccccccccccccccccccccccccccccccccc";
const CUSTODY_ATTEST_DIGEST: &str = "custody-att-digest-199";
const CUSTODY_KEY_ID: &str = "custody-key-id-199";
const SIGNER_ID: &str = "remote-signer-199";
const SIGNER_PUBID: &str = "remote-signer-pubid-199";
const ATTEST_DIGEST: &str = "remote-signer-attest-199";
const REQ_NONCE: &str = "req-nonce-199";
const RESP_NONCE: &str = "resp-nonce-199";
const NOW: u64 = 1_700_000_000;
const FRESH: u64 = 1_699_999_900;
const EXPIRES: u64 = 1_700_001_000;

// Selector tag spellings (must match RemoteSignerPolicy::tag exactly).
const TAG_DISABLED: &str = "disabled";
const TAG_FIXTURE: &str = "fixture-loopback-allowed";
const TAG_PRODUCTION: &str = "production-remote-signer-required";
const TAG_MAINNET: &str = "mainnet-production-remote-signer-required";

// ---------------------------------------------------------------------------
// Fixture builders — mirror the Run 196/198 corpus.
// ---------------------------------------------------------------------------

fn domain(env: TrustBundleEnvironment) -> AuthorityTrustDomain {
    AuthorityTrustDomain::new(env, CHAIN_ID, GENESIS_HASH, ROOT_FP, PQC_LIFECYCLE_SUITE_ML_DSA_44)
}

fn rotate_candidate(env: TrustBundleEnvironment) -> PersistentAuthorityStateRecordV2 {
    PersistentAuthorityStateRecordV2::new(
        CHAIN_ID.to_string(),
        env,
        GENESIS_HASH.to_string(),
        ROOT_FP.to_string(),
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        KEY_B.to_string(),
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        2,
        BundleSigningRatificationV2Action::Rotate,
        Some(KEY_A.to_string()),
        DIGEST_2.to_string(),
        None,
        AuthorityStateUpdateSource::TestOrFixture,
        NOW,
    )
}

fn prior_versioned(env: TrustBundleEnvironment) -> PersistentAuthorityStateRecordVersioned {
    PersistentAuthorityStateRecordVersioned::V2(PersistentAuthorityStateRecordV2::new(
        CHAIN_ID.to_string(),
        env,
        GENESIS_HASH.to_string(),
        ROOT_FP.to_string(),
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        KEY_A.to_string(),
        PQC_LIFECYCLE_SUITE_ML_DSA_44,
        1,
        BundleSigningRatificationV2Action::Ratify,
        None,
        PRIOR_DIGEST.to_string(),
        None,
        AuthorityStateUpdateSource::TestOrFixture,
        NOW,
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

fn request(env: TrustBundleEnvironment) -> RemoteSignerRequest {
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

fn fixture_signer(env: TrustBundleEnvironment) -> FixtureLoopbackRemoteSigner {
    FixtureLoopbackRemoteSigner {
        identity: identity(env),
        response_nonce: RESP_NONCE.to_string(),
        response_freshness_unix: Some(FRESH),
        response_expires_at_unix: Some(EXPIRES),
    }
}

fn fixture_response(env: TrustBundleEnvironment) -> RemoteSignerResponse {
    fixture_signer(env)
        .sign(&request(env))
        .expect("fixture loopback signs")
}

/// A well-formed response that claims `Production` signer mode. No real
/// production backend exists; the verifier refuses it as unavailable.
fn production_response(env: TrustBundleEnvironment) -> RemoteSignerResponse {
    let mut resp = fixture_response(env);
    resp.signer_mode = RemoteSignerMode::Production;
    resp
}

fn expectations() -> RemoteSignerExpectations {
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

fn custody_attestation(
    env: TrustBundleEnvironment,
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
        bundle_signing_key_fingerprint: KEY_B.to_string(),
        governance_authority_class: GovernanceAuthorityClass::GenesisBound,
        lifecycle_action: LocalLifecycleAction::Rotate,
        candidate_digest: DIGEST_2.to_string(),
        authority_domain_sequence: 2,
    }
}

/// Build the typed parts (identity/request/response) for `env`.
fn parts(env: TrustBundleEnvironment) -> RemoteSignerAttestationParts {
    RemoteSignerAttestationParts {
        identity: identity(env),
        request: request(env),
        response: fixture_response(env),
    }
}

/// Wrap parts as an `Available` load status by round-tripping through the
/// wire form (exercises the full payload-carrying parse path).
fn available_via_wire(p: &RemoteSignerAttestationParts) -> RemoteSignerLoadStatus {
    let wire = RemoteSignerAttestationWire::from_parts(&p.identity, &p.request, &p.response);
    let value = serde_json::json!({
        REMOTE_SIGNER_ATTESTATION_PAYLOAD_SIBLING_FIELD: serde_json::to_value(&wire).unwrap()
    });
    let loaded = parse_optional_remote_signer_attestation_sibling_from_json_value(&value);
    assert!(loaded.is_available(), "expected available, got {loaded:?}");
    loaded
}

/// Build a `Malformed` load status by mutating the wire before parse.
fn malformed_loaded(
    env: TrustBundleEnvironment,
    mutate: fn(&mut RemoteSignerAttestationWire),
) -> RemoteSignerLoadStatus {
    let p = parts(env);
    let mut wire = RemoteSignerAttestationWire::from_parts(&p.identity, &p.request, &p.response);
    mutate(&mut wire);
    let value = serde_json::json!({
        REMOTE_SIGNER_ATTESTATION_PAYLOAD_SIBLING_FIELD: serde_json::to_value(&wire).unwrap()
    });
    parse_optional_remote_signer_attestation_sibling_from_json_value(&value)
}

/// Owning bundle so a preflight wrapper / callsite context can borrow.
struct Ctx {
    custody: AuthorityCustodyAttestation,
    candidate: PersistentAuthorityStateRecordV2,
    prior: PersistentAuthorityStateRecordVersioned,
    domain: AuthorityTrustDomain,
    expected: RemoteSignerExpectations,
}

fn ctx_for(env: TrustBundleEnvironment, custody_class: AuthorityCustodyClass) -> Ctx {
    Ctx {
        custody: custody_attestation(env, custody_class),
        candidate: rotate_candidate(env),
        prior: prior_versioned(env),
        domain: domain(env),
        expected: expectations(),
    }
}

fn ctx_view<'a>(
    c: &'a Ctx,
    custody_policy: AuthorityCustodyPolicy,
    remote_signer_policy: RemoteSignerPolicy,
) -> RemoteSignerCallsiteContext<'a> {
    callsite_context_for_remote_signer(
        &c.custody,
        Some(&c.prior),
        &c.candidate,
        &c.domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        custody_policy,
        &c.expected,
        remote_signer_policy,
        NOW,
    )
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
        let prior = std::env::var(QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY_ENV).ok();
        match value {
            Some(v) => std::env::set_var(QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY_ENV, v),
            None => std::env::remove_var(QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY_ENV),
        }
        EnvGuard { prior }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.prior.take() {
            Some(v) => std::env::set_var(QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY_ENV, v),
            None => std::env::remove_var(QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY_ENV),
        }
    }
}

// ---------------------------------------------------------------------------
// Per-surface preflight dispatch — route a loaded carrier through one of the
// seven Run 198 preflight wrappers with the resolved RemoteSigner policy.
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

/// Drive the chosen per-surface Run 198 preflight wrapper with the given
/// resolved RemoteSigner policy and a parsed carrier. This is the chain the
/// run proves: CLI/env selector -> resolved RemoteSignerPolicy -> Run 198
/// preflight wrapper -> Run 196 routing helper -> Run 194 boundary.
#[allow(clippy::too_many_arguments)]
fn preflight(
    surface: Surface,
    c: &Ctx,
    custody_policy: AuthorityCustodyPolicy,
    remote_signer_policy: RemoteSignerPolicy,
    loaded: &RemoteSignerLoadStatus,
) -> RemoteSignerPayloadCarryingDecisionOutcome {
    let f = match surface {
        Surface::ReloadCheck => preflight_v2_marker_remote_signer_for_reload_check,
        Surface::ReloadApply => preflight_v2_marker_remote_signer_for_reload_apply,
        Surface::StartupP2p => preflight_v2_marker_remote_signer_for_startup_p2p_trust_bundle,
        Surface::Sighup => preflight_v2_marker_remote_signer_for_sighup,
        Surface::LocalPeerCandidate => {
            preflight_v2_marker_remote_signer_for_local_peer_candidate_check
        }
        Surface::LiveInbound0x05 => preflight_v2_marker_remote_signer_for_live_inbound_0x05,
        Surface::PeerDrivenDrain => preflight_v2_marker_remote_signer_for_peer_driven_drain,
    };
    f(
        &c.custody,
        Some(&c.prior),
        &c.candidate,
        &c.domain,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        custody_policy,
        &c.expected,
        remote_signer_policy,
        NOW,
        loaded,
    )
}

// ---------------------------------------------------------------------------
// Decision-outcome classification — a stable coarse tag we can compare
// against the typed `RemoteSignerPayloadCarryingDecisionOutcome` without
// echoing inner mismatch payloads.
// ---------------------------------------------------------------------------

/// First identifier of a Debug rendering, e.g. `WrongChain { .. }` => `WrongChain`.
fn variant_name<T: std::fmt::Debug>(v: &T) -> String {
    let s = format!("{:?}", v);
    s.split(|c| c == ' ' || c == '(' || c == '{')
        .next()
        .unwrap_or("")
        .to_string()
}

fn decision_tag(o: &RemoteSignerPayloadCarryingDecisionOutcome) -> String {
    if o.is_bypassed() {
        return "bypassed".to_string();
    }
    if o.is_required_but_absent() {
        return "required_but_absent".to_string();
    }
    if o.is_malformed_payload() {
        return "malformed_payload".to_string();
    }
    if o.is_mainnet_peer_driven_apply_refused() {
        return "mainnet_refused".to_string();
    }
    match o.callsite_outcome() {
        Some(LifecycleCustodyRemoteSignerOutcome::Accepted { .. }) => "accept".to_string(),
        Some(LifecycleCustodyRemoteSignerOutcome::RemoteSignerRejected {
            remote_signer_outcome,
            ..
        }) => format!("reject:{}", variant_name(remote_signer_outcome)),
        Some(LifecycleCustodyRemoteSignerOutcome::LifecycleOrCustodyRejected(_)) => {
            "lifecycle_or_custody_rejected".to_string()
        }
        Some(other) => format!("callsite:{}", variant_name(other)),
        None => "none".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Scenario corpus (A1..A11 / R1..R34 from `task/RUN_199_TASK.txt`).
//
// Each scenario routes a loaded carrier through one of the seven Run 198
// per-surface preflight wrappers with an explicitly resolved policy and
// compares the resulting decision outcome against its expected tag.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Carrier {
    Absent,
    /// `parts(env)` mutated by the fn, wrapped directly as `Available`.
    Available(fn(TrustBundleEnvironment, &mut RemoteSignerAttestationParts)),
    /// `parts(env)` round-tripped through the wire parse path.
    AvailableViaWire,
    /// `parts(env)` wire-encoded then mutated to fail closed at parse.
    Malformed(fn(&mut RemoteSignerAttestationWire)),
}

fn noop_parts(_env: TrustBundleEnvironment, _p: &mut RemoteSignerAttestationParts) {}
fn noop_ctx(_c: &mut Ctx) {}

struct ScenarioCase {
    id: &'static str,
    note: &'static str,
    env: TrustBundleEnvironment,
    custody_class: AuthorityCustodyClass,
    custody_policy: AuthorityCustodyPolicy,
    remote_signer_policy: RemoteSignerPolicy,
    surface: Surface,
    mutate_ctx: fn(&mut Ctx),
    carrier: Carrier,
    expected: &'static str,
}

fn build_carrier(env: TrustBundleEnvironment, carrier: &Carrier) -> RemoteSignerLoadStatus {
    match carrier {
        Carrier::Absent => RemoteSignerLoadStatus::Absent,
        Carrier::Available(f) => {
            let mut p = parts(env);
            f(env, &mut p);
            RemoteSignerLoadStatus::Available(p)
        }
        Carrier::AvailableViaWire => available_via_wire(&parts(env)),
        Carrier::Malformed(f) => malformed_loaded(env, *f),
    }
}

fn scenarios() -> Vec<ScenarioCase> {
    use AuthorityCustodyClass as Cls;
    use AuthorityCustodyPolicy as CPol;
    use RemoteSignerPolicy as RSPol;
    use Surface as S;
    use TrustBundleEnvironment as Env;
    vec![
        // --- Accepted / compatible A1–A11 routed through the preflight wrappers ---
        ScenarioCase {
            id: "A9",
            note: "no remote_signer payload compatible under default Disabled policy",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::Disabled,
            remote_signer_policy: RSPol::Disabled,
            surface: S::ReloadCheck,
            mutate_ctx: noop_ctx,
            carrier: Carrier::Absent,
            expected: "bypassed",
        },
        ScenarioCase {
            id: "A4",
            note: "devnet fixture loopback accepted under FixtureLoopbackAllowed (reload-check)",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::FixtureLoopbackAllowed,
            surface: S::ReloadCheck,
            mutate_ctx: noop_ctx,
            carrier: Carrier::AvailableViaWire,
            expected: "accept",
        },
        ScenarioCase {
            id: "A5",
            note: "testnet fixture loopback accepted under FixtureLoopbackAllowed (reload-check)",
            env: Env::Testnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::TestnetLocalAllowed,
            remote_signer_policy: RSPol::FixtureLoopbackAllowed,
            surface: S::ReloadCheck,
            mutate_ctx: noop_ctx,
            carrier: Carrier::AvailableViaWire,
            expected: "accept",
        },
        ScenarioCase {
            id: "A6",
            note: "production-remote-signer-required reaches production unavailable outcome",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::ProductionRemoteSignerRequired,
            surface: S::ReloadCheck,
            mutate_ctx: noop_ctx,
            carrier: Carrier::Available(|env, p| p.response = production_response(env)),
            expected: "reject:ProductionRemoteSignerUnavailable",
        },
        ScenarioCase {
            id: "A7",
            note: "mainnet-production-remote-signer-required reaches mainnet unavailable outcome",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::MainnetProductionRemoteSignerRequired,
            surface: S::ReloadCheck,
            mutate_ctx: noop_ctx,
            carrier: Carrier::Available(|env, p| p.response = production_response(env)),
            expected: "reject:MainNetProductionRemoteSignerUnavailable",
        },
        ScenarioCase {
            id: "A10-startup",
            note: "fixture loopback accepted (startup p2p) under FixtureLoopbackAllowed",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::FixtureLoopbackAllowed,
            surface: S::StartupP2p,
            mutate_ctx: noop_ctx,
            carrier: Carrier::AvailableViaWire,
            expected: "accept",
        },
        ScenarioCase {
            id: "A10-reload-apply",
            note: "fixture loopback accepted (reload-apply) under FixtureLoopbackAllowed",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::FixtureLoopbackAllowed,
            surface: S::ReloadApply,
            mutate_ctx: noop_ctx,
            carrier: Carrier::AvailableViaWire,
            expected: "accept",
        },
        ScenarioCase {
            id: "A10-sighup",
            note: "fixture loopback accepted (SIGHUP) under FixtureLoopbackAllowed",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::FixtureLoopbackAllowed,
            surface: S::Sighup,
            mutate_ctx: noop_ctx,
            carrier: Carrier::AvailableViaWire,
            expected: "accept",
        },
        ScenarioCase {
            id: "A10-localpeer",
            note: "fixture loopback accepted (local peer-candidate check) under FixtureLoopbackAllowed",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::FixtureLoopbackAllowed,
            surface: S::LocalPeerCandidate,
            mutate_ctx: noop_ctx,
            carrier: Carrier::AvailableViaWire,
            expected: "accept",
        },
        ScenarioCase {
            id: "A11",
            note: "live inbound 0x05 receives selected policy and accepts fixture loopback",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::FixtureLoopbackAllowed,
            surface: S::LiveInbound0x05,
            mutate_ctx: noop_ctx,
            carrier: Carrier::AvailableViaWire,
            expected: "accept",
        },
        // --- Rejection R4–R34 routed through the preflight wrappers ---
        ScenarioCase {
            id: "R4",
            note: "no remote_signer payload rejected under FixtureLoopbackAllowed",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::FixtureLoopbackAllowed,
            surface: S::ReloadCheck,
            mutate_ctx: noop_ctx,
            carrier: Carrier::Absent,
            expected: "required_but_absent",
        },
        ScenarioCase {
            id: "R5",
            note: "no remote_signer payload rejected under ProductionRemoteSignerRequired",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::ProductionRemoteSignerRequired,
            surface: S::ReloadCheck,
            mutate_ctx: noop_ctx,
            carrier: Carrier::Absent,
            expected: "required_but_absent",
        },
        ScenarioCase {
            id: "R6",
            note: "fixture loopback rejected under ProductionRemoteSignerRequired",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::ProductionRemoteSignerRequired,
            surface: S::ReloadCheck,
            mutate_ctx: noop_ctx,
            carrier: Carrier::Available(noop_parts),
            expected: "reject:FixtureRejectedProductionRequired",
        },
        ScenarioCase {
            id: "R7",
            note: "fixture loopback rejected under MainnetProductionRemoteSignerRequired",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::MainnetProductionRemoteSignerRequired,
            surface: S::ReloadCheck,
            mutate_ctx: noop_ctx,
            carrier: Carrier::Available(noop_parts),
            expected: "reject:FixtureRejectedMainnetProductionRequired",
        },
        ScenarioCase {
            id: "R8",
            note: "production rejected as unavailable",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::FixtureLoopbackAllowed,
            surface: S::ReloadCheck,
            mutate_ctx: noop_ctx,
            carrier: Carrier::Available(|env, p| p.response = production_response(env)),
            expected: "reject:ProductionRemoteSignerUnavailable",
        },
        ScenarioCase {
            id: "R9",
            note: "mainnet production rejected as unavailable",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::MainnetProductionRemoteSignerRequired,
            surface: S::ReloadCheck,
            mutate_ctx: noop_ctx,
            carrier: Carrier::Available(|env, p| p.response = production_response(env)),
            expected: "reject:MainNetProductionRemoteSignerUnavailable",
        },
        ScenarioCase {
            id: "R10",
            note: "wrong environment rejected",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::FixtureLoopbackAllowed,
            surface: S::ReloadCheck,
            mutate_ctx: noop_ctx,
            carrier: Carrier::Available(|_e, p| p.request.environment = Env::Testnet),
            expected: "reject:WrongEnvironment",
        },
        ScenarioCase {
            id: "R11",
            note: "wrong chain rejected",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::FixtureLoopbackAllowed,
            surface: S::ReloadCheck,
            mutate_ctx: noop_ctx,
            carrier: Carrier::Available(|_e, p| p.request.chain_id = OTHER_CHAIN.to_string()),
            expected: "reject:WrongChain",
        },
        ScenarioCase {
            id: "R12",
            note: "wrong genesis rejected",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::FixtureLoopbackAllowed,
            surface: S::ReloadCheck,
            mutate_ctx: noop_ctx,
            carrier: Carrier::Available(|_e, p| p.request.genesis_hash = OTHER_GENESIS.to_string()),
            expected: "reject:WrongGenesis",
        },
        ScenarioCase {
            id: "R13",
            note: "wrong authority root rejected",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::FixtureLoopbackAllowed,
            surface: S::ReloadCheck,
            mutate_ctx: noop_ctx,
            carrier: Carrier::Available(|_e, p| {
                p.request.authority_root_fingerprint = OTHER_ROOT_FP.to_string()
            }),
            expected: "reject:WrongAuthorityRoot",
        },
        ScenarioCase {
            id: "R14",
            note: "wrong custody key id rejected",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::FixtureLoopbackAllowed,
            surface: S::ReloadCheck,
            mutate_ctx: noop_ctx,
            carrier: Carrier::Available(|_e, p| {
                p.response.custody_key_id = "wrong-custody-key".to_string()
            }),
            expected: "reject:WrongCustodyKeyId",
        },
        ScenarioCase {
            id: "R15",
            note: "wrong signing key fingerprint rejected",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::FixtureLoopbackAllowed,
            surface: S::ReloadCheck,
            mutate_ctx: noop_ctx,
            carrier: Carrier::Available(|_e, p| {
                p.request.new_signing_key_fingerprint = Some(OTHER_SIGNING_FP.to_string())
            }),
            expected: "reject:WrongSigningKeyFingerprint",
        },
        ScenarioCase {
            id: "R16",
            note: "wrong lifecycle action rejected",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::FixtureLoopbackAllowed,
            surface: S::ReloadCheck,
            mutate_ctx: noop_ctx,
            carrier: Carrier::Available(|_e, p| {
                p.request.lifecycle_action = LocalLifecycleAction::Revoke
            }),
            expected: "reject:WrongLifecycleAction",
        },
        ScenarioCase {
            id: "R17",
            note: "wrong candidate digest rejected",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::FixtureLoopbackAllowed,
            surface: S::ReloadCheck,
            mutate_ctx: noop_ctx,
            carrier: Carrier::Available(|_e, p| p.request.candidate_digest = DIGEST_OTHER.to_string()),
            expected: "reject:WrongCandidateDigest",
        },
        ScenarioCase {
            id: "R18",
            note: "wrong authority domain sequence rejected",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::FixtureLoopbackAllowed,
            surface: S::ReloadCheck,
            mutate_ctx: noop_ctx,
            carrier: Carrier::Available(|_e, p| p.request.authority_domain_sequence = 7),
            expected: "reject:WrongAuthorityDomainSequence",
        },
        ScenarioCase {
            id: "R19",
            note: "wrong request digest rejected",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::FixtureLoopbackAllowed,
            surface: S::ReloadCheck,
            mutate_ctx: noop_ctx,
            carrier: Carrier::Available(|_e, p| p.response.request_digest = "deadbeef".to_string()),
            expected: "reject:WrongRequestDigest",
        },
        ScenarioCase {
            id: "R20",
            note: "stale or replayed request rejected",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::FixtureLoopbackAllowed,
            surface: S::ReloadCheck,
            mutate_ctx: noop_ctx,
            carrier: Carrier::Available(|_e, p| {
                p.request.replay_nonce = "stale-req-nonce".to_string();
                p.response.request_digest = p.request.canonical_digest();
            }),
            expected: "reject:StaleOrReplayedRequest",
        },
        ScenarioCase {
            id: "R21",
            note: "stale or replayed response rejected",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::FixtureLoopbackAllowed,
            surface: S::ReloadCheck,
            mutate_ctx: noop_ctx,
            carrier: Carrier::Available(|_e, p| {
                p.response.response_nonce = "stale-resp-nonce".to_string()
            }),
            expected: "reject:StaleOrReplayedResponse",
        },
        ScenarioCase {
            id: "R22",
            note: "expired attestation rejected",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::FixtureLoopbackAllowed,
            surface: S::ReloadCheck,
            mutate_ctx: noop_ctx,
            carrier: Carrier::Available(|_e, p| p.identity.expires_at_unix = Some(NOW - 1)),
            expected: "reject:ExpiredAttestation",
        },
        ScenarioCase {
            id: "R23",
            note: "expired response rejected",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::FixtureLoopbackAllowed,
            surface: S::ReloadCheck,
            mutate_ctx: noop_ctx,
            carrier: Carrier::Available(|_e, p| p.response.expires_at_unix = Some(NOW - 1)),
            expected: "reject:ExpiredResponse",
        },
        ScenarioCase {
            id: "R24",
            note: "unsupported suite rejected",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::FixtureLoopbackAllowed,
            surface: S::ReloadCheck,
            mutate_ctx: noop_ctx,
            carrier: Carrier::Available(|_e, p| p.response.signature_suite_id = 0xEE),
            expected: "reject:UnsupportedSuite",
        },
        ScenarioCase {
            id: "R25",
            note: "invalid / placeholder signature rejected",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::FixtureLoopbackAllowed,
            surface: S::ReloadCheck,
            mutate_ctx: noop_ctx,
            carrier: Carrier::Available(|_e, p| {
                p.response.signature_commitment =
                    REMOTE_SIGNER_INVALID_SIGNATURE_SENTINEL.to_string()
            }),
            expected: "reject:InvalidSignature",
        },
        ScenarioCase {
            id: "R26",
            note: "malformed RemoteSigner material rejected (parse short-circuit)",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::FixtureLoopbackAllowed,
            surface: S::ReloadCheck,
            mutate_ctx: noop_ctx,
            carrier: Carrier::Malformed(|w| w.identity.signer_public_identity = String::new()),
            expected: "malformed_payload",
        },
        ScenarioCase {
            id: "R29",
            note: "RemoteSigner valid but custody metadata invalid rejected",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::FixtureLoopbackAllowed,
            surface: S::ReloadCheck,
            mutate_ctx: |c| c.custody.candidate_digest = DIGEST_OTHER.to_string(),
            carrier: Carrier::AvailableViaWire,
            expected: "lifecycle_or_custody_rejected",
        },
        ScenarioCase {
            id: "R30",
            note: "custody valid but RemoteSigner response invalid rejected",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::FixtureLoopbackAllowed,
            surface: S::ReloadCheck,
            mutate_ctx: noop_ctx,
            carrier: Carrier::Available(|_e, p| {
                p.response.signature_commitment =
                    REMOTE_SIGNER_INVALID_SIGNATURE_SENTINEL.to_string()
            }),
            expected: "reject:InvalidSignature",
        },
        ScenarioCase {
            id: "R33",
            note: "invalid live 0x05 RemoteSigner material not propagated (malformed payload)",
            env: Env::Devnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::FixtureLoopbackAllowed,
            surface: S::LiveInbound0x05,
            mutate_ctx: noop_ctx,
            carrier: Carrier::Malformed(|w| w.response.response_nonce = String::new()),
            expected: "malformed_payload",
        },
        ScenarioCase {
            id: "R34",
            note: "mainnet peer-driven apply refused even with MainnetProductionRemoteSignerRequired + fixture loopback",
            env: Env::Mainnet,
            custody_class: Cls::FixtureLocalKey,
            custody_policy: CPol::DevnetLocalAllowed,
            remote_signer_policy: RSPol::MainnetProductionRemoteSignerRequired,
            surface: S::PeerDrivenDrain,
            mutate_ctx: noop_ctx,
            carrier: Carrier::AvailableViaWire,
            expected: "mainnet_refused",
        },
    ]
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

// ---------------------------------------------------------------------------
// Table 1 — selector resolution (default / CLI / env / precedence / invalid).
// Exercises the Run 198 resolver `remote_signer_policy_from_cli_or_env`,
// `remote_signer_policy_env_selector`, and `remote_signer_policy_from_selector`
// in release mode.
// ---------------------------------------------------------------------------

fn run_selector_resolution_table(out: &Path) -> (u64, u64) {
    let mut buf = String::new();
    let mut pass = 0u64;
    let mut fail = 0u64;
    let mut record = |name: &str, ok: bool, detail: &str| {
        if ok {
            pass += 1;
        } else {
            fail += 1;
        }
        buf.push_str(&format!("{}\t{}\t{}\n", name, if ok { "PASS" } else { "FAIL" }, detail));
    };

    // S1 — default (no CLI, no env) resolves to Disabled.
    {
        let _g = EnvGuard::set(None);
        let resolved = remote_signer_policy_from_cli_or_env(None);
        record(
            "S1-default-absent-is-disabled",
            resolved == Ok(RemoteSignerPolicy::Disabled),
            &format!("resolved={resolved:?}"),
        );
    }

    // S2 — CLI selector resolves each canonical tag (env unset).
    {
        let _g = EnvGuard::set(None);
        let cli_cases = [
            (TAG_DISABLED, RemoteSignerPolicy::Disabled),
            (TAG_FIXTURE, RemoteSignerPolicy::FixtureLoopbackAllowed),
            (TAG_PRODUCTION, RemoteSignerPolicy::ProductionRemoteSignerRequired),
            (TAG_MAINNET, RemoteSignerPolicy::MainnetProductionRemoteSignerRequired),
        ];
        for (tag, expected) in cli_cases {
            let resolved = remote_signer_policy_from_cli_or_env(Some(tag));
            record(
                &format!("S2-cli-{tag}"),
                resolved == Ok(expected),
                &format!("cli={tag:?} resolved={resolved:?}"),
            );
        }
    }

    // S3 — env selector resolves each canonical tag (CLI absent).
    {
        let env_cases = [
            (TAG_DISABLED, RemoteSignerPolicy::Disabled),
            (TAG_FIXTURE, RemoteSignerPolicy::FixtureLoopbackAllowed),
            (TAG_PRODUCTION, RemoteSignerPolicy::ProductionRemoteSignerRequired),
            (TAG_MAINNET, RemoteSignerPolicy::MainnetProductionRemoteSignerRequired),
        ];
        for (tag, expected) in env_cases {
            let _g = EnvGuard::set(Some(tag));
            let via_env = remote_signer_policy_env_selector();
            let resolved = remote_signer_policy_from_cli_or_env(None);
            record(
                &format!("S3-env-{tag}"),
                via_env == Ok(Some(expected)) && resolved == Ok(expected),
                &format!("env={tag:?} via_env={via_env:?} resolved={resolved:?}"),
            );
        }
    }

    // S4 — CLI-over-env precedence is deterministic: env fixture, CLI
    // disabled -> Disabled.
    {
        let _g = EnvGuard::set(Some(TAG_FIXTURE));
        let resolved = remote_signer_policy_from_cli_or_env(Some(TAG_DISABLED));
        record(
            "S4-cli-over-env-precedence",
            resolved == Ok(RemoteSignerPolicy::Disabled),
            &format!("env=fixture cli=disabled resolved={resolved:?}"),
        );
    }
    {
        // ... and the reverse direction is equally deterministic.
        let _g = EnvGuard::set(Some(TAG_DISABLED));
        let resolved = remote_signer_policy_from_cli_or_env(Some(TAG_FIXTURE));
        record(
            "S4-cli-over-env-precedence-reverse",
            resolved == Ok(RemoteSignerPolicy::FixtureLoopbackAllowed),
            &format!("env=disabled cli=fixture resolved={resolved:?}"),
        );
    }

    // R1 — invalid CLI selector value fails closed with a typed error.
    {
        let _g = EnvGuard::set(None);
        let err = remote_signer_policy_from_cli_or_env(Some("kms-required"));
        record(
            "R1-invalid-cli-rejected",
            matches!(
                err,
                Err(RemoteSignerPolicySelectorParseError::UnknownValue { .. })
            ),
            &format!("err={err:?}"),
        );
        let empty = remote_signer_policy_from_cli_or_env(Some("   "));
        record(
            "R1-empty-cli-rejected",
            empty == Err(RemoteSignerPolicySelectorParseError::Empty),
            &format!("empty={empty:?}"),
        );
    }

    // R2 — invalid env selector value fails closed with a typed error.
    {
        let _g = EnvGuard::set(Some("hsm-required"));
        let via_env = remote_signer_policy_env_selector();
        let resolved = remote_signer_policy_from_cli_or_env(None);
        record(
            "R2-invalid-env-rejected",
            matches!(
                via_env,
                Err(RemoteSignerPolicySelectorParseError::UnknownValue { .. })
            ) && resolved.is_err(),
            &format!("via_env={via_env:?} resolved={resolved:?}"),
        );
    }

    // R3 — an unrelated env var does not enable the RemoteSigner policy.
    {
        let _g = EnvGuard::set(None);
        std::env::set_var("QBIND_SOME_UNRELATED_FLAG_199", "fixture-loopback-allowed");
        let resolved = remote_signer_policy_from_cli_or_env(None);
        std::env::remove_var("QBIND_SOME_UNRELATED_FLAG_199");
        record(
            "R3-unrelated-env-stays-disabled",
            resolved == Ok(RemoteSignerPolicy::Disabled),
            &format!("resolved={resolved:?}"),
        );
    }

    // Case-insensitive / trimmed matching is honored by the pure parser.
    {
        let resolved = remote_signer_policy_from_selector("  FIXTURE-LOOPBACK-ALLOWED  ");
        record(
            "parser-case-insensitive-trim",
            resolved == Ok(RemoteSignerPolicy::FixtureLoopbackAllowed),
            &format!("resolved={resolved:?}"),
        );
    }

    write_file(&out.join("selector_resolution_table.txt"), &buf);
    (pass, fail)
}

// ---------------------------------------------------------------------------
// Table 2 — A1..A11 / R4..R34 decision scenarios through the preflight wrappers.
// ---------------------------------------------------------------------------

fn run_scenarios(out: &Path) -> (u64, u64) {
    let cases = scenarios();
    let mut manifest = String::new();
    let mut expected_lines = String::new();
    let mut actual_lines = String::new();
    let mut pass = 0u64;
    let mut fail = 0u64;
    for case in &cases {
        let mut c = ctx_for(case.env, case.custody_class);
        (case.mutate_ctx)(&mut c);
        let loaded = build_carrier(case.env, &case.carrier);
        let outcome = preflight(
            case.surface,
            &c,
            case.custody_policy,
            case.remote_signer_policy,
            &loaded,
        );
        let actual = decision_tag(&outcome);
        let ok = actual == case.expected;
        if ok {
            pass += 1;
        } else {
            fail += 1;
        }
        manifest.push_str(&format!(
            "{}\t{}\tsurface={}\texpected={}\tactual={}\t{}\n",
            case.id,
            if ok { "PASS" } else { "FAIL" },
            surface_name(case.surface),
            case.expected,
            actual,
            case.note
        ));
        expected_lines.push_str(&format!("{}\t{}\n", case.id, case.expected));
        actual_lines.push_str(&format!("{}\t{}\n", case.id, actual));
        let dir = out.join("scenarios").join(case.id);
        write_file(&dir.join("note.txt"), &format!("{}\n", case.note));
        write_file(&dir.join("expected.txt"), &format!("{}\n", case.expected));
        write_file(&dir.join("actual.txt"), &format!("{}\n", actual));
    }
    write_file(&out.join("manifest.txt"), &manifest);
    write_file(&out.join("expected_outcomes.txt"), &expected_lines);
    write_file(&out.join("actual_outcomes.txt"), &actual_lines);
    (pass, fail)
}

// ---------------------------------------------------------------------------
// Table 3 — resolved policy reaches all seven preflight surfaces.
// ---------------------------------------------------------------------------

fn run_seven_surface_reachability(out: &Path) -> (u64, u64) {
    let mut buf = String::new();
    let mut pass = 0u64;
    let mut fail = 0u64;
    let mut record = |name: &str, ok: bool, detail: &str| {
        if ok {
            pass += 1;
        } else {
            fail += 1;
        }
        buf.push_str(&format!("{}\t{}\t{}\n", name, if ok { "PASS" } else { "FAIL" }, detail));
    };

    // FixtureLoopbackAllowed + valid DevNet carrier: accept at every
    // non-MainNet surface (peer-driven drain accepts a non-MainNet candidate).
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
    let loaded = available_via_wire(&parts(TrustBundleEnvironment::Devnet));
    for surface in ALL_SURFACES {
        let outcome = preflight(
            surface,
            &c,
            AuthorityCustodyPolicy::DevnetLocalAllowed,
            RemoteSignerPolicy::FixtureLoopbackAllowed,
            &loaded,
        );
        record(
            &format!("reach-accept-{}", surface_name(surface)),
            outcome.is_accept(),
            &format!("outcome={}", decision_tag(&outcome)),
        );
    }

    // Required-but-absent under an explicit non-Disabled policy fails closed
    // at every surface (proves the selected policy reaches each one).
    let absent = RemoteSignerLoadStatus::Absent;
    for surface in ALL_SURFACES {
        let outcome = preflight(
            surface,
            &c,
            AuthorityCustodyPolicy::DevnetLocalAllowed,
            RemoteSignerPolicy::FixtureLoopbackAllowed,
            &absent,
        );
        record(
            &format!("reach-required-absent-{}", surface_name(surface)),
            outcome.is_required_but_absent() && outcome.is_reject(),
            &format!("outcome={}", decision_tag(&outcome)),
        );
    }

    write_file(&out.join("seven_surface_reachability_table.txt"), &buf);
    (pass, fail)
}

// ---------------------------------------------------------------------------
// Table 4 — custody-class routing (RemoteSigner class accepts fixture; local
// operator / KMS / HSM cannot satisfy the RemoteSigner boundary).
// ---------------------------------------------------------------------------

fn run_custody_routing_table(out: &Path) -> (u64, u64) {
    let rows: &[(&str, AuthorityCustodyClass, &str)] = &[
        ("RemoteSigner", AuthorityCustodyClass::RemoteSigner, "FixtureLoopbackAccepted"),
        (
            "R27-LocalOperatorKey",
            AuthorityCustodyClass::LocalOperatorKey,
            "LocalOperatorKeyCannotSatisfyRemoteSigner",
        ),
        ("Kms", AuthorityCustodyClass::Kms, "NotRemoteSignerCustodyClass"),
        ("Hsm", AuthorityCustodyClass::Hsm, "NotRemoteSignerCustodyClass"),
    ];
    let mut buf = String::new();
    let mut pass = 0u64;
    let mut fail = 0u64;
    for (id, class, expected) in rows {
        let c = ctx_for(TrustBundleEnvironment::Devnet, *class);
        let ctx = ctx_view(
            &c,
            AuthorityCustodyPolicy::DevnetLocalAllowed,
            RemoteSignerPolicy::FixtureLoopbackAllowed,
        );
        let loaded = available_via_wire(&parts(TrustBundleEnvironment::Devnet));
        let outcome = route_remote_signer_attestation_for_custody_class(*class, &ctx, &loaded);
        let actual = variant_name(&outcome);
        let ok = &actual == expected;
        if ok {
            pass += 1;
        } else {
            fail += 1;
        }
        buf.push_str(&format!(
            "{}\t{}\tclass={:?}\texpected={}\tactual={}\n",
            id,
            if ok { "PASS" } else { "FAIL" },
            class,
            expected,
            actual
        ));
    }
    write_file(&out.join("custody_routing_table.txt"), &buf);
    (pass, fail)
}

// ---------------------------------------------------------------------------
// Table 5 — A10 governance + other-custody bypass invariants when the
// RemoteSigner policy is Disabled.
// ---------------------------------------------------------------------------

fn run_governance_bypass_table(out: &Path) -> (u64, u64) {
    let mut buf = String::new();
    let mut pass = 0u64;
    let mut fail = 0u64;

    // Governance classes unchanged when RemoteSigner policy Disabled.
    for class in [
        GovernanceAuthorityClass::GenesisBound,
        GovernanceAuthorityClass::EmergencyCouncil,
        GovernanceAuthorityClass::OnChainGovernance,
    ] {
        let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
        let outcome = preflight_v2_marker_remote_signer_for_reload_check(
            &c.custody,
            Some(&c.prior),
            &c.candidate,
            &c.domain,
            class,
            LocalLifecycleAction::Rotate,
            DIGEST_2,
            2,
            Some(CUSTODY_KEY_ID),
            AuthorityCustodyPolicy::Disabled,
            &c.expected,
            RemoteSignerPolicy::Disabled,
            NOW,
            &RemoteSignerLoadStatus::Absent,
        );
        let ok = outcome.is_bypassed();
        if ok {
            pass += 1;
        } else {
            fail += 1;
        }
        buf.push_str(&format!(
            "A10-gov\t{}\tgovernance={:?}\tbypassed={}\n",
            if ok { "PASS" } else { "FAIL" },
            class,
            outcome.is_bypassed()
        ));
    }

    // Other custody paths compatible with RemoteSigner absent under Disabled.
    for class in [
        AuthorityCustodyClass::FixtureLocalKey,
        AuthorityCustodyClass::LocalOperatorKey,
        AuthorityCustodyClass::Kms,
        AuthorityCustodyClass::Hsm,
    ] {
        let c = ctx_for(TrustBundleEnvironment::Devnet, class);
        let outcome = preflight(
            Surface::ReloadCheck,
            &c,
            AuthorityCustodyPolicy::Disabled,
            RemoteSignerPolicy::Disabled,
            &RemoteSignerLoadStatus::Absent,
        );
        let ok = outcome.is_bypassed();
        if ok {
            pass += 1;
        } else {
            fail += 1;
        }
        buf.push_str(&format!(
            "A9-custody\t{}\tcustody={:?}\tbypassed={}\n",
            if ok { "PASS" } else { "FAIL" },
            class,
            outcome.is_bypassed()
        ));
    }

    write_file(&out.join("governance_bypass_table.txt"), &buf);
    (pass, fail)
}

// ---------------------------------------------------------------------------
// Table 6 — combined v2 sidecar loader (Run 190 custody + Run 196 RemoteSigner).
// ---------------------------------------------------------------------------

fn make_v2_sidecar_value(
    env: TrustBundleEnvironment,
    remote_signer_sibling: Option<serde_json::Value>,
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
    if let Some(p) = remote_signer_sibling {
        value
            .as_object_mut()
            .unwrap()
            .insert(REMOTE_SIGNER_ATTESTATION_PAYLOAD_SIBLING_FIELD.to_string(), p);
    }
    value
}

fn run_loader_table(out: &Path) -> (u64, u64) {
    let mut buf = String::new();
    let mut pass = 0u64;
    let mut fail = 0u64;
    let mut record = |name: &str, ok: bool, detail: &str| {
        if ok {
            pass += 1;
        } else {
            fail += 1;
        }
        buf.push_str(&format!("{}\t{}\t{}\n", name, if ok { "PASS" } else { "FAIL" }, detail));
    };

    // Legacy v2 sidecar without the sibling yields Absent.
    let legacy = make_v2_sidecar_value(TrustBundleEnvironment::Devnet, None);
    let legacy_bytes = serde_json::to_vec(&legacy).unwrap();
    let legacy_path = PathBuf::from("/dev/null/run-199-legacy.json");
    let legacy_loaded = load_v2_ratification_sidecar_with_remote_signer_attestation_from_bytes(
        &legacy_bytes,
        &legacy_path,
    )
    .expect("legacy v2 sidecar parses");
    record(
        "loader-legacy-absent",
        legacy_loaded.remote_signer_attestation.is_absent(),
        "no remote_signer_attestation sibling -> Absent",
    );

    // v2 sidecar with the sibling yields Available with matching parts.
    let p = parts(TrustBundleEnvironment::Devnet);
    let wire = RemoteSignerAttestationWire::from_parts(&p.identity, &p.request, &p.response);
    let carry = make_v2_sidecar_value(
        TrustBundleEnvironment::Devnet,
        Some(serde_json::to_value(&wire).unwrap()),
    );
    let carry_bytes = serde_json::to_vec(&carry).unwrap();
    let carry_path = PathBuf::from("/dev/null/run-199-carry.json");
    let carry_loaded = load_v2_ratification_sidecar_with_remote_signer_attestation_from_bytes(
        &carry_bytes,
        &carry_path,
    )
    .expect("v2 sidecar with sibling parses");
    record(
        "loader-sibling-available",
        carry_loaded.remote_signer_attestation.is_available()
            && carry_loaded.remote_signer_attestation.as_parts() == Some(&p),
        "remote_signer_attestation sibling -> Available(parts)",
    );

    write_file(&out.join("loader_table.txt"), &buf);
    (pass, fail)
}

// ---------------------------------------------------------------------------
// Table 7 — refusal helpers + reachability of the Run 194 verifier through
// the payload-carrying boundary (R27 / R28 / MainNet helper /
// validate_loaded_remote_signer).
// ---------------------------------------------------------------------------

fn run_refusal_helpers_table(out: &Path) -> (u64, u64) {
    let mut buf = String::new();
    let mut pass = 0u64;
    let mut fail = 0u64;
    let mut record = |name: &str, ok: bool, detail: &str| {
        if ok {
            pass += 1;
        } else {
            fail += 1;
        }
        buf.push_str(&format!("{}\t{}\t{}\n", name, if ok { "PASS" } else { "FAIL" }, detail));
    };

    // R28 — peer majority cannot satisfy the RemoteSigner boundary.
    record(
        "R28-peer-majority-cannot-satisfy",
        peer_majority_cannot_satisfy_remote_signer(),
        "peer_majority_cannot_satisfy_remote_signer() == true",
    );

    // MainNet peer-driven apply remains refused under payload carrying.
    record(
        "mainnet-refused-helper",
        mainnet_peer_driven_apply_remains_refused_under_remote_signer_payload_carrying(
            TrustBundleEnvironment::Mainnet,
        ) && !mainnet_peer_driven_apply_remains_refused_under_remote_signer_payload_carrying(
            TrustBundleEnvironment::Devnet,
        ),
        "mainnet=true, devnet=false",
    );

    // validate_loaded_remote_signer reachability: Available -> Some(accept),
    // Absent -> None.
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
    let ctx = ctx_view(
        &c,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
    );
    let available = available_via_wire(&parts(TrustBundleEnvironment::Devnet));
    let routed = validate_loaded_remote_signer(&ctx, &available);
    record(
        "validate_loaded_remote_signer-available-accepts",
        matches!(routed, Some(RemoteSignerOutcome::FixtureLoopbackAccepted { .. })),
        &format!("routed={routed:?}"),
    );
    let routed_absent = validate_loaded_remote_signer(&ctx, &RemoteSignerLoadStatus::Absent);
    record(
        "validate_loaded_remote_signer-absent-none",
        routed_absent.is_none(),
        "absent carrier -> None",
    );

    write_file(&out.join("refusal_helpers_table.txt"), &buf);
    (pass, fail)
}

// ---------------------------------------------------------------------------
// Table 8 — no-mutation + determinism evidence (R31 / R32).
// ---------------------------------------------------------------------------

fn run_no_mutation_evidence(out: &Path) -> (u64, u64) {
    let mut buf = String::new();
    let mut pass = 0u64;
    let mut fail = 0u64;
    let mut record = |name: &str, ok: bool, detail: &str| {
        if ok {
            pass += 1;
        } else {
            fail += 1;
        }
        buf.push_str(&format!("{}\t{}\t{}\n", name, if ok { "PASS" } else { "FAIL" }, detail));
    };

    // R31 — validation-only preflight wrappers are pure and deterministic.
    let c = ctx_for(TrustBundleEnvironment::Devnet, AuthorityCustodyClass::FixtureLocalKey);
    let loaded = malformed_loaded(TrustBundleEnvironment::Devnet, |w| {
        w.response.signature_commitment = String::new()
    });
    let a = preflight(
        Surface::ReloadCheck,
        &c,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        &loaded,
    );
    let b = preflight(
        Surface::LocalPeerCandidate,
        &c,
        AuthorityCustodyPolicy::DevnetLocalAllowed,
        RemoteSignerPolicy::FixtureLoopbackAllowed,
        &loaded,
    );
    record(
        "R31-pure-deterministic",
        a.is_reject() && a == b,
        "reload-check == local-peer-candidate-check",
    );

    // R32 — mutating-preflight wrappers short-circuit a malformed carrier
    // before the verifier (and therefore before any sequence/marker write or
    // Run 070 call).
    let loaded2 = malformed_loaded(TrustBundleEnvironment::Devnet, |w| {
        w.identity.attestation_digest = String::new()
    });
    for surface in [Surface::ReloadApply, Surface::StartupP2p, Surface::Sighup] {
        let outcome = preflight(
            surface,
            &c,
            AuthorityCustodyPolicy::DevnetLocalAllowed,
            RemoteSignerPolicy::FixtureLoopbackAllowed,
            &loaded2,
        );
        record(
            &format!("R32-{}-malformed-shortcircuit", surface_name(surface)),
            outcome.is_malformed_payload()
                && outcome.is_reject()
                && outcome.callsite_outcome().is_none(),
            "verifier not reached; no mutation reachable",
        );
    }

    write_file(&out.join("no_mutation_evidence.txt"), &buf);
    (pass, fail)
}

fn run_determinism_check(out: &Path) -> (u64, u64) {
    let cases = scenarios();
    let mut buf = String::new();
    let mut pass = 0u64;
    let mut fail = 0u64;
    for case in &cases {
        let mut tags = Vec::new();
        for _ in 0..3 {
            let mut c = ctx_for(case.env, case.custody_class);
            (case.mutate_ctx)(&mut c);
            let loaded = build_carrier(case.env, &case.carrier);
            tags.push(decision_tag(&preflight(
                case.surface,
                &c,
                case.custody_policy,
                case.remote_signer_policy,
                &loaded,
            )));
        }
        let ok = tags.iter().all(|t| t == &tags[0]);
        if ok {
            pass += 1;
        } else {
            fail += 1;
        }
        buf.push_str(&format!(
            "{}\t{}\t{}\n",
            case.id,
            if ok { "PASS" } else { "FAIL" },
            tags.join(",")
        ));
    }
    write_file(&out.join("determinism_evidence.txt"), &buf);
    (pass, fail)
}

fn run_fixture_dump(out: &Path) {
    let p = parts(TrustBundleEnvironment::Devnet);
    write_file(
        &out.join("fixtures").join("request.txt"),
        &format!("{:#?}\n", p.request),
    );
    write_file(
        &out.join("fixtures").join("response.txt"),
        &format!("{:#?}\n", p.response),
    );
    let wire = RemoteSignerAttestationWire::from_parts(&p.identity, &p.request, &p.response);
    write_file(
        &out.join("fixtures").join("wire.txt"),
        &format!("{}\n", serde_json::to_string_pretty(&wire).unwrap()),
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
            eprintln!("usage: run_199_remote_signer_policy_release_binary_helper <OUT_DIR>");
            std::process::exit(2);
        }
    };
    fs::create_dir_all(&out_dir).unwrap_or_else(|e| panic!("create out dir {out_dir:?}: {e}"));

    let tables: &[(&str, fn(&Path) -> (u64, u64))] = &[
        ("selector_resolution", run_selector_resolution_table),
        ("scenarios", run_scenarios),
        ("seven_surface_reachability", run_seven_surface_reachability),
        ("custody_routing", run_custody_routing_table),
        ("governance_bypass", run_governance_bypass_table),
        ("loader", run_loader_table),
        ("refusal_helpers", run_refusal_helpers_table),
        ("no_mutation", run_no_mutation_evidence),
        ("determinism", run_determinism_check),
    ];

    let mut total_pass = 0u64;
    let mut total_fail = 0u64;
    let mut summary = String::new();
    summary.push_str("run_199_remote_signer_policy_release_binary_helper\n");
    summary.push_str("scope: Run 198 hidden RemoteSigner policy selector + Run 196 payload-carrying / production-context boundary (release binary)\n");
    summary.push_str("note: fixture-only; no real RemoteSigner/KMS/HSM/governance backend; no live trust mutation; no P2P socket; MainNet peer-driven apply remains refused\n\n");
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