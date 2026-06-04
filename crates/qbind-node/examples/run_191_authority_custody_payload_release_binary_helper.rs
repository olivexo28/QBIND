//! Run 191 — release-built helper that exercises the Run 190
//! authority-custody **payload-carrying** corpus end-to-end **in
//! release mode** through the production library symbols
//! [`qbind_node::pqc_authority_custody_payload_carrying`] and
//! [`qbind_node::pqc_authority_custody`].
//!
//! Per `task/RUN_191_TASK.txt`, Run 191 is the release-binary evidence
//! run for the Run 190 source/test typed authority-custody metadata
//! carrying + per-surface routing layer. This helper is fixture-only
//! tooling and:
//!
//! * does NOT modify any production runtime code, CLI flag, env var,
//!   wire / marker / sequence / trust-bundle / peer-candidate-envelope
//!   schema beyond what Runs 070, 130–190 already established;
//! * does NOT enable MainNet peer-driven apply on any surface;
//! * does NOT mutate any live trust state, write any marker, advance
//!   any sequence, swap any live trust, evict any session, or invoke
//!   Run 070;
//! * does NOT open any P2P socket;
//! * does NOT implement any real KMS / HSM / cloud-KMS / PKCS#11 /
//!   remote-signer backend; every `RemoteSigner` / `Kms` / `Hsm`
//!   placeholder routes to the Run 188 typed `*Unavailable` reject;
//! * never elevates fixture / local-operator custody into MainNet
//!   production custody (MainNet always refuses at the typed
//!   boundary ahead of the policy gate);
//! * exists alongside (and does NOT replace) the Run 190 source/test
//!   target
//!   `crates/qbind-node/tests/run_190_authority_custody_payload_callsite_tests.rs`.
//!
//! The helper writes the following files under `<OUT_DIR>/`:
//!
//! ```text
//! <OUT_DIR>/manifest.txt              # one row per scenario (id\texpected\tmatch\tno_mutation)
//! <OUT_DIR>/expected_outcomes.txt
//! <OUT_DIR>/actual_outcomes.txt
//! <OUT_DIR>/scenarios/<id>/{policy,expected,actual,note}.txt
//! <OUT_DIR>/wire_round_trip.txt
//! <OUT_DIR>/sibling_parse_table.txt
//! <OUT_DIR>/routing_helpers_table.txt
//! <OUT_DIR>/named_helpers_table.txt
//! <OUT_DIR>/no_mutation_evidence.txt
//! <OUT_DIR>/determinism_evidence.txt
//! <OUT_DIR>/helper_summary.txt
//! ```
//!
//! The helper exits non-zero if any scenario does not match its
//! expected typed outcome.
//!
//! Usage:
//! ```text
//! run_191_authority_custody_payload_release_binary_helper <OUT_DIR>
//! ```

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use qbind_ledger::BundleSigningRatificationV2Action;
use qbind_node::pqc_authority_custody::{
    local_operator_config_alone_cannot_satisfy_mainnet_production_custody,
    mainnet_peer_driven_apply_remains_refused_under_custody_boundary,
    peer_majority_cannot_satisfy_custody, AuthorityCustodyAttestation, AuthorityCustodyClass,
    AuthorityCustodyPolicy, AuthorityCustodyValidationOutcome, LifecycleGovernanceCustodyOutcome,
};
use qbind_node::pqc_authority_custody_payload_carrying::{
    callsite_context_for_authority_custody,
    mainnet_peer_driven_apply_remains_refused_under_custody_payload_carrying,
    parse_optional_authority_custody_attestation_sibling_from_json_value,
    route_loaded_authority_custody_attestation_to_live_inbound_0x05_callsite_decision,
    route_loaded_authority_custody_attestation_to_local_peer_candidate_check_callsite_decision,
    route_loaded_authority_custody_attestation_to_peer_driven_drain_callsite_decision,
    route_loaded_authority_custody_attestation_to_reload_apply_callsite_decision,
    route_loaded_authority_custody_attestation_to_reload_check_callsite_decision,
    route_loaded_authority_custody_attestation_to_sighup_callsite_decision,
    route_loaded_authority_custody_attestation_to_startup_p2p_trust_bundle_callsite_decision,
    AuthorityCustodyAttestationWire, AuthorityCustodyCallsiteContext, AuthorityCustodyClassWire,
    AuthorityCustodyLoadStatus, AuthorityCustodyPayloadCarryingDecisionOutcome,
    GovernanceAuthorityClassWire, AUTHORITY_CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD,
    AUTHORITY_CUSTODY_ATTESTATION_WIRE_SCHEMA_VERSION,
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
// Constants — kept structurally identical to the Run 190 test fixtures so the
// typed payload-carrying semantics carry over end-to-end in release mode.
// ---------------------------------------------------------------------------

const KEY_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEY_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ROOT_FP: &str = "1111111111111111111111111111111111111111";
const CHAIN_ID: &str = "0000000000000001";
const GENESIS_HASH: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const PRIOR_DIGEST: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";
const CUSTODY_ATTEST_DIGEST: &str = "custody-att-digest-191";
const CUSTODY_KEY_ID: &str = "custody-key-id-191";
const NOW: u64 = 1_700_000_000;
const FRESH: u64 = 1_699_999_900;
const EXPIRES: u64 = 1_700_001_000;

// ---------------------------------------------------------------------------
// Fixture builders — mirror `tests/run_190_authority_custody_payload_callsite_tests.rs`.
// ---------------------------------------------------------------------------

fn domain_for(env: TrustBundleEnvironment) -> AuthorityTrustDomain {
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

fn good_attestation(
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

fn ctx_for<'a>(
    persisted: Option<&'a PersistentAuthorityStateRecordVersioned>,
    candidate: &'a PersistentAuthorityStateRecordV2,
    domain: &'a AuthorityTrustDomain,
    policy: AuthorityCustodyPolicy,
) -> AuthorityCustodyCallsiteContext<'a> {
    callsite_context_for_authority_custody(
        persisted,
        candidate,
        domain,
        policy,
        GovernanceAuthorityClass::GenesisBound,
        LocalLifecycleAction::Rotate,
        DIGEST_2,
        2,
        Some(CUSTODY_KEY_ID),
        NOW,
    )
}

fn wire_for(att: &AuthorityCustodyAttestation) -> AuthorityCustodyAttestationWire {
    AuthorityCustodyAttestationWire::from_attestation(att)
}

fn sibling_value_for(att: &AuthorityCustodyAttestation) -> serde_json::Value {
    serde_json::json!({
        AUTHORITY_CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD:
            serde_json::to_value(wire_for(att)).unwrap()
    })
}

fn loaded_for(att: &AuthorityCustodyAttestation) -> AuthorityCustodyLoadStatus {
    parse_optional_authority_custody_attestation_sibling_from_json_value(&sibling_value_for(att))
}

fn loaded_absent() -> AuthorityCustodyLoadStatus {
    parse_optional_authority_custody_attestation_sibling_from_json_value(&serde_json::json!({}))
}

fn loaded_malformed_json() -> AuthorityCustodyLoadStatus {
    // sibling present but not a valid wire object (string instead of struct).
    parse_optional_authority_custody_attestation_sibling_from_json_value(&serde_json::json!({
        AUTHORITY_CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD: "not-an-object"
    }))
}

fn loaded_malformed_wire_unknown_schema() -> AuthorityCustodyLoadStatus {
    let candidate = rotate_candidate(TrustBundleEnvironment::Devnet);
    let att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &candidate,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let mut wire = AuthorityCustodyAttestationWire::from_attestation(&att);
    wire.schema_version = 9999;
    parse_optional_authority_custody_attestation_sibling_from_json_value(&serde_json::json!({
        AUTHORITY_CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD:
            serde_json::to_value(wire).unwrap()
    }))
}

// ---------------------------------------------------------------------------
// Symbolic expected outcome.
// ---------------------------------------------------------------------------

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum Expect {
    /// Carrier absent + policy Disabled: legacy bypass.
    NoCustodyAttestationSupplied,
    /// Carrier malformed at JSON or wire layer.
    MalformedAuthorityCustodyAttestationPayload,
    /// Carrier absent under non-Disabled policy.
    CustodyAttestationRequiredButAbsent,
    /// Peer-driven drain MainNet refusal.
    MainNetPeerDrivenApplyRefused,
    /// Run 188 fixture acceptance via combined helper.
    CallsiteAcceptedFixture,
    /// Run 188 local-operator acceptance via combined helper.
    CallsiteAcceptedLocalOperator,
    /// Run 188 KMS placeholder fail-closed.
    CallsiteCustodyRejectedKmsUnavailable,
    /// Run 188 HSM placeholder fail-closed.
    CallsiteCustodyRejectedHsmUnavailable,
    /// Run 188 RemoteSigner placeholder fail-closed.
    CallsiteCustodyRejectedRemoteSignerUnavailable,
    /// Run 188 fixture-on-MainNet refusal.
    CallsiteCustodyRejectedFixtureOnMainNet,
    /// Run 188 local-operator-on-MainNet refusal.
    CallsiteCustodyRejectedLocalOnMainNet,
    /// Run 188 policy refuses class (e.g. fixture under
    /// ProductionCustodyRequired).
    CallsiteCustodyRejectedPolicyRefusesClass,
    /// Run 188 production-custody-required policy fail-closed
    /// (no real production backend).
    CallsiteCustodyRejectedProductionUnavailable,
    /// Run 188 unknown-class rejection.
    CallsiteCustodyRejectedUnknownClass,
}

fn matches_expect(actual: &AuthorityCustodyPayloadCarryingDecisionOutcome, expected: &Expect) -> bool {
    match (actual, expected) {
        (
            AuthorityCustodyPayloadCarryingDecisionOutcome::NoCustodyAttestationSupplied,
            Expect::NoCustodyAttestationSupplied,
        ) => true,
        (
            AuthorityCustodyPayloadCarryingDecisionOutcome::MalformedAuthorityCustodyAttestationPayload(_),
            Expect::MalformedAuthorityCustodyAttestationPayload,
        ) => true,
        (
            AuthorityCustodyPayloadCarryingDecisionOutcome::CustodyAttestationRequiredButAbsent { .. },
            Expect::CustodyAttestationRequiredButAbsent,
        ) => true,
        (
            AuthorityCustodyPayloadCarryingDecisionOutcome::MainNetPeerDrivenApplyRefused,
            Expect::MainNetPeerDrivenApplyRefused,
        ) => true,
        (AuthorityCustodyPayloadCarryingDecisionOutcome::Callsite(c), e) => match (c, e) {
            (
                LifecycleGovernanceCustodyOutcome::Accepted { custody_outcome, .. },
                Expect::CallsiteAcceptedFixture,
            ) => matches!(
                custody_outcome,
                AuthorityCustodyValidationOutcome::AcceptedFixtureCustody { .. }
            ),
            (
                LifecycleGovernanceCustodyOutcome::Accepted { custody_outcome, .. },
                Expect::CallsiteAcceptedLocalOperator,
            ) => matches!(
                custody_outcome,
                AuthorityCustodyValidationOutcome::AcceptedLocalOperatorCustody { .. }
            ),
            (
                LifecycleGovernanceCustodyOutcome::CustodyRejected { custody_outcome, .. },
                Expect::CallsiteCustodyRejectedKmsUnavailable,
            ) => matches!(custody_outcome, AuthorityCustodyValidationOutcome::KmsUnavailable),
            (
                LifecycleGovernanceCustodyOutcome::CustodyRejected { custody_outcome, .. },
                Expect::CallsiteCustodyRejectedHsmUnavailable,
            ) => matches!(custody_outcome, AuthorityCustodyValidationOutcome::HsmUnavailable),
            (
                LifecycleGovernanceCustodyOutcome::CustodyRejected { custody_outcome, .. },
                Expect::CallsiteCustodyRejectedRemoteSignerUnavailable,
            ) => matches!(
                custody_outcome,
                AuthorityCustodyValidationOutcome::RemoteSignerUnavailable
            ),
            (
                LifecycleGovernanceCustodyOutcome::CustodyRejected { custody_outcome, .. },
                Expect::CallsiteCustodyRejectedFixtureOnMainNet,
            ) => matches!(
                custody_outcome,
                AuthorityCustodyValidationOutcome::FixtureCustodyRejectedForMainNet
            ),
            (
                LifecycleGovernanceCustodyOutcome::CustodyRejected { custody_outcome, .. },
                Expect::CallsiteCustodyRejectedLocalOnMainNet,
            ) => matches!(
                custody_outcome,
                AuthorityCustodyValidationOutcome::LocalCustodyRejectedForMainNet
            ),
            (
                LifecycleGovernanceCustodyOutcome::CustodyRejected { custody_outcome, .. },
                Expect::CallsiteCustodyRejectedPolicyRefusesClass,
            ) => matches!(
                custody_outcome,
                AuthorityCustodyValidationOutcome::PolicyRefusesCustodyClass { .. }
            ),
            (
                LifecycleGovernanceCustodyOutcome::CustodyRejected { custody_outcome, .. },
                Expect::CallsiteCustodyRejectedProductionUnavailable,
            ) => matches!(
                custody_outcome,
                AuthorityCustodyValidationOutcome::ProductionCustodyUnavailable { .. }
            ),
            (
                LifecycleGovernanceCustodyOutcome::CustodyRejected { custody_outcome, .. },
                Expect::CallsiteCustodyRejectedUnknownClass,
            ) => matches!(
                custody_outcome,
                AuthorityCustodyValidationOutcome::UnknownCustodyClassRejected
            ),
            _ => false,
        },
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Routing-helper labels — every scenario is replayed across all seven
// production routing helpers so reachability is captured by symbol.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum Surface {
    ReloadCheck,
    ReloadApply,
    StartupP2pTrustBundle,
    Sighup,
    LocalPeerCandidateCheck,
    LiveInbound0x05,
    PeerDrivenDrain,
}

impl Surface {
    const ALL: [Surface; 7] = [
        Surface::ReloadCheck,
        Surface::ReloadApply,
        Surface::StartupP2pTrustBundle,
        Surface::Sighup,
        Surface::LocalPeerCandidateCheck,
        Surface::LiveInbound0x05,
        Surface::PeerDrivenDrain,
    ];

    fn label(self) -> &'static str {
        match self {
            Surface::ReloadCheck => "reload_check",
            Surface::ReloadApply => "reload_apply",
            Surface::StartupP2pTrustBundle => "startup_p2p_trust_bundle",
            Surface::Sighup => "sighup",
            Surface::LocalPeerCandidateCheck => "local_peer_candidate_check",
            Surface::LiveInbound0x05 => "live_inbound_0x05",
            Surface::PeerDrivenDrain => "peer_driven_drain",
        }
    }

    fn route(
        self,
        ctx: &AuthorityCustodyCallsiteContext<'_>,
        loaded: &AuthorityCustodyLoadStatus,
    ) -> AuthorityCustodyPayloadCarryingDecisionOutcome {
        match self {
            Surface::ReloadCheck => {
                route_loaded_authority_custody_attestation_to_reload_check_callsite_decision(
                    ctx, loaded,
                )
            }
            Surface::ReloadApply => {
                route_loaded_authority_custody_attestation_to_reload_apply_callsite_decision(
                    ctx, loaded,
                )
            }
            Surface::StartupP2pTrustBundle => {
                route_loaded_authority_custody_attestation_to_startup_p2p_trust_bundle_callsite_decision(
                    ctx, loaded,
                )
            }
            Surface::Sighup => {
                route_loaded_authority_custody_attestation_to_sighup_callsite_decision(ctx, loaded)
            }
            Surface::LocalPeerCandidateCheck => {
                route_loaded_authority_custody_attestation_to_local_peer_candidate_check_callsite_decision(
                    ctx, loaded,
                )
            }
            Surface::LiveInbound0x05 => {
                route_loaded_authority_custody_attestation_to_live_inbound_0x05_callsite_decision(
                    ctx, loaded,
                )
            }
            Surface::PeerDrivenDrain => {
                route_loaded_authority_custody_attestation_to_peer_driven_drain_callsite_decision(
                    ctx, loaded,
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Scenario corpus (A1–A10 / R1–R32 from `task/RUN_191_TASK.txt`).
// ---------------------------------------------------------------------------

struct Scenario {
    id: &'static str,
    note: &'static str,
    env: TrustBundleEnvironment,
    policy: AuthorityCustodyPolicy,
    /// `None` => carrier absent. `Some(class)` => carrier present with
    /// `good_attestation` of the given class for `env`. Special-cased
    /// strings handle malformed payload + MainNet-binding mismatches.
    carrier: Carrier,
    /// Surface to evaluate. Some scenarios are surface-specific
    /// (peer-driven drain MainNet refusal); others apply to all 7.
    surfaces: SurfaceSet,
    /// Expected typed outcome on the *primary* surface (the one
    /// distinguishing this scenario from the broader corpus). Other
    /// surfaces have the same expectation unless `peer_drain_mainnet`
    /// is set.
    expected: Expect,
    /// If true, the peer-driven drain surface refuses with
    /// `MainNetPeerDrivenApplyRefused` regardless of `expected`.
    peer_drain_mainnet: bool,
}

#[derive(Debug, Clone)]
enum Carrier {
    Absent,
    Present(AuthorityCustodyClass),
    PresentWithEnv {
        class: AuthorityCustodyClass,
        attestation_env: TrustBundleEnvironment,
    },
    MalformedJson,
    MalformedWireUnknownSchema,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SurfaceSet {
    All,
    PeerDrivenDrainOnly,
}

fn corpus() -> Vec<Scenario> {
    use AuthorityCustodyClass::*;
    use AuthorityCustodyPolicy::*;
    use Carrier::*;
    use TrustBundleEnvironment::*;

    vec![
        // A1. legacy no-custody payload remains compatible under
        // default Disabled.
        Scenario {
            id: "A1_no_custody_devnet_disabled",
            note: "legacy payload + Disabled => NoCustodyAttestationSupplied",
            env: Devnet,
            policy: Disabled,
            carrier: Absent,
            surfaces: SurfaceSet::All,
            expected: Expect::NoCustodyAttestationSupplied,
            peer_drain_mainnet: false,
        },
        // A2. DevNet fixture custody under FixtureOnly accepted.
        Scenario {
            id: "A2_devnet_fixture_under_fixture_only",
            note: "DevNet fixture custody accepted under FixtureOnly via every routing helper",
            env: Devnet,
            policy: FixtureOnly,
            carrier: Present(FixtureLocalKey),
            surfaces: SurfaceSet::All,
            expected: Expect::CallsiteAcceptedFixture,
            peer_drain_mainnet: false,
        },
        // A3. TestNet fixture custody under FixtureOnly accepted.
        Scenario {
            id: "A3_testnet_fixture_under_fixture_only",
            note: "TestNet fixture custody accepted under FixtureOnly via every routing helper",
            env: Testnet,
            policy: FixtureOnly,
            carrier: Present(FixtureLocalKey),
            surfaces: SurfaceSet::All,
            expected: Expect::CallsiteAcceptedFixture,
            peer_drain_mainnet: false,
        },
        // A4. DevNet local-operator custody under DevnetLocalAllowed
        // accepted.
        Scenario {
            id: "A4_devnet_local_under_devnet_local_allowed",
            note: "DevNet local-operator custody accepted under DevnetLocalAllowed",
            env: Devnet,
            policy: DevnetLocalAllowed,
            carrier: Present(LocalOperatorKey),
            surfaces: SurfaceSet::All,
            expected: Expect::CallsiteAcceptedLocalOperator,
            peer_drain_mainnet: false,
        },
        // A5. TestNet local-operator custody under TestnetLocalAllowed
        // accepted.
        Scenario {
            id: "A5_testnet_local_under_testnet_local_allowed",
            note: "TestNet local-operator custody accepted under TestnetLocalAllowed",
            env: Testnet,
            policy: TestnetLocalAllowed,
            carrier: Present(LocalOperatorKey),
            surfaces: SurfaceSet::All,
            expected: Expect::CallsiteAcceptedLocalOperator,
            peer_drain_mainnet: false,
        },
        // A6. DevNet fixture custody routed through reload-apply
        // surface (also tested across all 7 surfaces — same accept).
        Scenario {
            id: "A6_devnet_fixture_reload_apply",
            note: "DevNet fixture custody accepted via reload-apply (and every other routing surface)",
            env: Devnet,
            policy: FixtureOnly,
            carrier: Present(FixtureLocalKey),
            surfaces: SurfaceSet::All,
            expected: Expect::CallsiteAcceptedFixture,
            peer_drain_mainnet: false,
        },
        // A7. combined lifecycle + governance + fixture custody
        // accepted for DevNet.
        Scenario {
            id: "A7_devnet_combined_fixture_accept",
            note: "DevNet combined lifecycle+governance+fixture custody accepted",
            env: Devnet,
            policy: FixtureOnly,
            carrier: Present(FixtureLocalKey),
            surfaces: SurfaceSet::All,
            expected: Expect::CallsiteAcceptedFixture,
            peer_drain_mainnet: false,
        },
        // A8. combined lifecycle + governance + local custody accepted
        // for TestNet.
        Scenario {
            id: "A8_testnet_combined_local_accept",
            note: "TestNet combined lifecycle+governance+local-operator custody accepted",
            env: Testnet,
            policy: TestnetLocalAllowed,
            carrier: Present(LocalOperatorKey),
            surfaces: SurfaceSet::All,
            expected: Expect::CallsiteAcceptedLocalOperator,
            peer_drain_mainnet: false,
        },
        // A9. GenesisBound proof path remains compatible when custody
        // validation is Disabled (carrier absent => bypass).
        Scenario {
            id: "A9_genesis_bound_no_custody_disabled_bypass",
            note: "GenesisBound + custody Disabled + no carrier => legacy bypass",
            env: Devnet,
            policy: Disabled,
            carrier: Absent,
            surfaces: SurfaceSet::All,
            expected: Expect::NoCustodyAttestationSupplied,
            peer_drain_mainnet: false,
        },
        // A10. KMS placeholder reaches Run 188 validator and returns
        // typed unavailable outcome (a "reach" success — the routing
        // helper successfully delivered the placeholder to the
        // validator, which then fail-closed).
        Scenario {
            id: "A10_kms_placeholder_reaches_validator_unavailable",
            note: "KMS placeholder routes to Run 188 validator and returns KmsUnavailable",
            env: Devnet,
            policy: ProductionCustodyRequired,
            carrier: Present(Kms),
            surfaces: SurfaceSet::All,
            expected: Expect::CallsiteCustodyRejectedKmsUnavailable,
            peer_drain_mainnet: false,
        },
        // R1. carrier absent under non-Disabled policy => required-
        // but-absent.
        Scenario {
            id: "R1_required_but_absent",
            note: "carrier absent under FixtureOnly => CustodyAttestationRequiredButAbsent",
            env: Devnet,
            policy: FixtureOnly,
            carrier: Absent,
            surfaces: SurfaceSet::All,
            expected: Expect::CustodyAttestationRequiredButAbsent,
            peer_drain_mainnet: false,
        },
        // R2. malformed JSON sibling => malformed payload.
        Scenario {
            id: "R2_malformed_json_sibling",
            note: "JSON-malformed sibling => MalformedAuthorityCustodyAttestationPayload",
            env: Devnet,
            policy: FixtureOnly,
            carrier: MalformedJson,
            surfaces: SurfaceSet::All,
            expected: Expect::MalformedAuthorityCustodyAttestationPayload,
            peer_drain_mainnet: false,
        },
        // R2b. malformed wire (unknown schema_version) => malformed
        // payload (covered by Run 190 §wire-form regressions).
        Scenario {
            id: "R2b_malformed_wire_unknown_schema",
            note: "wire schema_version mismatch => MalformedAuthorityCustodyAttestationPayload",
            env: Devnet,
            policy: FixtureOnly,
            carrier: MalformedWireUnknownSchema,
            surfaces: SurfaceSet::All,
            expected: Expect::MalformedAuthorityCustodyAttestationPayload,
            peer_drain_mainnet: false,
        },
        // R3. fixture custody under ProductionCustodyRequired =>
        // ProductionCustodyUnavailable (no real backend).
        Scenario {
            id: "R3_fixture_under_production_required",
            note: "fixture under ProductionCustodyRequired => ProductionCustodyUnavailable",
            env: Devnet,
            policy: ProductionCustodyRequired,
            carrier: Present(FixtureLocalKey),
            surfaces: SurfaceSet::All,
            expected: Expect::CallsiteCustodyRejectedProductionUnavailable,
            peer_drain_mainnet: false,
        },
        // R4. local-operator under ProductionCustodyRequired =>
        // ProductionCustodyUnavailable.
        Scenario {
            id: "R4_local_under_production_required",
            note: "local-operator under ProductionCustodyRequired => ProductionCustodyUnavailable",
            env: Devnet,
            policy: ProductionCustodyRequired,
            carrier: Present(LocalOperatorKey),
            surfaces: SurfaceSet::All,
            expected: Expect::CallsiteCustodyRejectedProductionUnavailable,
            peer_drain_mainnet: false,
        },
        // R5. fixture custody on MainNet => FixtureCustodyRejectedForMainNet
        // (peer-driven drain still refuses MainNet first).
        Scenario {
            id: "R5_fixture_on_mainnet",
            note: "fixture on MainNet trust domain => FixtureCustodyRejectedForMainNet (peer-driven drain refuses MainNet ahead)",
            env: TrustBundleEnvironment::Mainnet,
            policy: FixtureOnly,
            carrier: PresentWithEnv {
                class: FixtureLocalKey,
                attestation_env: TrustBundleEnvironment::Mainnet,
            },
            surfaces: SurfaceSet::All,
            expected: Expect::CallsiteCustodyRejectedFixtureOnMainNet,
            peer_drain_mainnet: true,
        },
        // R6. local-operator on MainNet => LocalCustodyRejectedForMainNet.
        Scenario {
            id: "R6_local_on_mainnet",
            note: "local-operator on MainNet trust domain => LocalCustodyRejectedForMainNet",
            env: TrustBundleEnvironment::Mainnet,
            policy: DevnetLocalAllowed,
            carrier: PresentWithEnv {
                class: LocalOperatorKey,
                attestation_env: TrustBundleEnvironment::Mainnet,
            },
            surfaces: SurfaceSet::All,
            expected: Expect::CallsiteCustodyRejectedLocalOnMainNet,
            peer_drain_mainnet: true,
        },
        // R7. KMS unavailable.
        Scenario {
            id: "R7_kms_unavailable",
            note: "KMS placeholder => KmsUnavailable",
            env: Devnet,
            policy: ProductionCustodyRequired,
            carrier: Present(Kms),
            surfaces: SurfaceSet::All,
            expected: Expect::CallsiteCustodyRejectedKmsUnavailable,
            peer_drain_mainnet: false,
        },
        // R8. HSM unavailable.
        Scenario {
            id: "R8_hsm_unavailable",
            note: "HSM placeholder => HsmUnavailable",
            env: Devnet,
            policy: ProductionCustodyRequired,
            carrier: Present(Hsm),
            surfaces: SurfaceSet::All,
            expected: Expect::CallsiteCustodyRejectedHsmUnavailable,
            peer_drain_mainnet: false,
        },
        // R9. RemoteSigner unavailable.
        Scenario {
            id: "R9_remote_signer_unavailable",
            note: "RemoteSigner placeholder => RemoteSignerUnavailable",
            env: Devnet,
            policy: ProductionCustodyRequired,
            carrier: Present(RemoteSigner),
            surfaces: SurfaceSet::All,
            expected: Expect::CallsiteCustodyRejectedRemoteSignerUnavailable,
            peer_drain_mainnet: false,
        },
        // R10. unknown custody class => UnknownCustodyClassRejected.
        Scenario {
            id: "R10_unknown_custody_class",
            note: "Unknown custody class => UnknownCustodyClassRejected",
            env: Devnet,
            policy: FixtureOnly,
            carrier: Present(Unknown),
            surfaces: SurfaceSet::All,
            expected: Expect::CallsiteCustodyRejectedUnknownClass,
            peer_drain_mainnet: false,
        },
        // R26. lifecycle valid + governance valid + custody placeholder
        // unavailable rejected (covered by R7/R8/R9 — extra Hsm pass
        // through reload_apply mutating-preflight surface for
        // explicitness; reuses HSM reject path).
        Scenario {
            id: "R26_combined_placeholder_unavailable",
            note: "lifecycle+governance valid + custody Hsm placeholder => HsmUnavailable on every routing surface",
            env: Devnet,
            policy: ProductionCustodyRequired,
            carrier: Present(Hsm),
            surfaces: SurfaceSet::All,
            expected: Expect::CallsiteCustodyRejectedHsmUnavailable,
            peer_drain_mainnet: false,
        },
        // R32. MainNet peer-driven apply remains refused even with
        // custody metadata claiming KMS / HSM.
        Scenario {
            id: "R32_mainnet_peer_drain_refused_with_kms",
            note: "MainNet peer-driven drain refuses regardless of KMS custody attestation",
            env: TrustBundleEnvironment::Mainnet,
            policy: ProductionCustodyRequired,
            carrier: PresentWithEnv {
                class: Kms,
                attestation_env: TrustBundleEnvironment::Mainnet,
            },
            surfaces: SurfaceSet::PeerDrivenDrainOnly,
            expected: Expect::MainNetPeerDrivenApplyRefused,
            peer_drain_mainnet: true,
        },
        // R31. invalid live 0x05 custody-metadata candidate not
        // propagated/staged/applied — the routing helper for live
        // inbound 0x05 short-circuits as a malformed payload.
        Scenario {
            id: "R31_live_0x05_invalid_candidate",
            note: "live 0x05 surface short-circuits malformed custody payload before staging",
            env: Devnet,
            policy: FixtureOnly,
            carrier: MalformedJson,
            surfaces: SurfaceSet::All,
            expected: Expect::MalformedAuthorityCustodyAttestationPayload,
            peer_drain_mainnet: false,
        },
    ]
}

fn build_loaded(scn: &Scenario) -> AuthorityCustodyLoadStatus {
    match &scn.carrier {
        Carrier::Absent => loaded_absent(),
        Carrier::Present(class) => {
            let cand = rotate_candidate(scn.env);
            let att = good_attestation(scn.env, &cand, *class);
            loaded_for(&att)
        }
        Carrier::PresentWithEnv { class, attestation_env } => {
            let cand = rotate_candidate(scn.env);
            let mut att = good_attestation(scn.env, &cand, *class);
            att.environment = *attestation_env;
            loaded_for(&att)
        }
        Carrier::MalformedJson => loaded_malformed_json(),
        Carrier::MalformedWireUnknownSchema => loaded_malformed_wire_unknown_schema(),
    }
}

fn run_routing_corpus(
    out_dir: &Path,
    manifest: &mut String,
    expected_buf: &mut String,
    actual_buf: &mut String,
) -> std::io::Result<(usize, usize)> {
    let mut pass = 0usize;
    let mut fail = 0usize;
    let scenarios = corpus();
    let scenarios_dir = out_dir.join("scenarios");
    fs::create_dir_all(&scenarios_dir)?;

    for scn in &scenarios {
        let cand = rotate_candidate(scn.env);
        let prior = prior_versioned(scn.env);
        let dom = domain_for(scn.env);
        let ctx = ctx_for(Some(&prior), &cand, &dom, scn.policy);
        let loaded = build_loaded(scn);

        let surfaces: Vec<Surface> = match scn.surfaces {
            SurfaceSet::All => Surface::ALL.to_vec(),
            SurfaceSet::PeerDrivenDrainOnly => vec![Surface::PeerDrivenDrain],
        };

        let scn_dir = scenarios_dir.join(scn.id);
        fs::create_dir_all(&scn_dir)?;
        fs::write(scn_dir.join("policy.txt"), format!("{:?}\n", scn.policy))?;
        fs::write(scn_dir.join("expected.txt"), format!("{:?}\n", scn.expected))?;
        fs::write(scn_dir.join("note.txt"), format!("{}\n", scn.note))?;
        let mut actual_lines = String::new();

        for surface in surfaces {
            let outcome = surface.route(&ctx, &loaded);
            let expected = if matches!(surface, Surface::PeerDrivenDrain) && scn.peer_drain_mainnet {
                Expect::MainNetPeerDrivenApplyRefused
            } else {
                scn.expected.clone()
            };
            let m = matches_expect(&outcome, &expected);
            if m {
                pass += 1;
            } else {
                fail += 1;
                eprintln!(
                    "[run-191-helper] FAIL scenario={} surface={} expected={:?} actual={:?}",
                    scn.id,
                    surface.label(),
                    expected,
                    outcome
                );
            }
            let line = format!(
                "{}\t{}\t{:?}\t{:?}\tmatch={}\n",
                scn.id,
                surface.label(),
                expected,
                outcome,
                m
            );
            actual_lines.push_str(&line);
            manifest.push_str(&format!(
                "{}\t{}\t{:?}\t{:?}\tmatch={}\n",
                scn.id,
                surface.label(),
                expected,
                outcome,
                m
            ));
            expected_buf.push_str(&format!(
                "{}\t{}\t{:?}\n",
                scn.id,
                surface.label(),
                expected
            ));
            actual_buf.push_str(&format!(
                "{}\t{}\t{:?}\n",
                scn.id,
                surface.label(),
                outcome
            ));
        }
        fs::write(scn_dir.join("actual.txt"), actual_lines)?;
    }
    Ok((pass, fail))
}

// ---------------------------------------------------------------------------
// Wire round-trip: every AuthorityCustodyClass and GovernanceAuthorityClass
// round-trip through Wire / from_attestation / to_attestation cleanly.
// ---------------------------------------------------------------------------

fn run_wire_round_trip(out_dir: &Path) -> std::io::Result<(usize, usize)> {
    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut buf = String::new();

    buf.push_str(&format!(
        "AUTHORITY_CUSTODY_ATTESTATION_WIRE_SCHEMA_VERSION\t{}\n",
        AUTHORITY_CUSTODY_ATTESTATION_WIRE_SCHEMA_VERSION
    ));
    buf.push_str(&format!(
        "AUTHORITY_CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD\t{}\n",
        AUTHORITY_CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD
    ));

    let mut record = |label: &str, ok: bool| {
        if ok {
            pass += 1;
        } else {
            fail += 1;
            eprintln!("[run-191-helper] FAIL wire round-trip: {}", label);
        }
        buf.push_str(&format!("{}\tok={}\n", label, ok));
    };

    record(
        "schema_version_is_one",
        AUTHORITY_CUSTODY_ATTESTATION_WIRE_SCHEMA_VERSION == 1,
    );
    record(
        "sibling_field_name_is_canonical",
        AUTHORITY_CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD == "authority_custody_attestation",
    );

    for c in [
        AuthorityCustodyClass::FixtureLocalKey,
        AuthorityCustodyClass::LocalOperatorKey,
        AuthorityCustodyClass::RemoteSigner,
        AuthorityCustodyClass::Kms,
        AuthorityCustodyClass::Hsm,
        AuthorityCustodyClass::Unknown,
    ] {
        let wire = AuthorityCustodyClassWire::from_class(c);
        record(
            &format!("class_round_trip_{:?}", c),
            wire.to_class() == c,
        );
    }
    for g in [
        GovernanceAuthorityClass::GenesisBound,
        GovernanceAuthorityClass::EmergencyCouncil,
        GovernanceAuthorityClass::OnChainGovernance,
    ] {
        let wire = GovernanceAuthorityClassWire::from_class(g);
        record(
            &format!("gov_class_round_trip_{:?}", g),
            wire.to_class() == g,
        );
    }

    // Full attestation wire round-trip across DevNet/TestNet.
    for env in [TrustBundleEnvironment::Devnet, TrustBundleEnvironment::Testnet] {
        let cand = rotate_candidate(env);
        let att = good_attestation(env, &cand, AuthorityCustodyClass::FixtureLocalKey);
        let wire = AuthorityCustodyAttestationWire::from_attestation(&att);
        let back = wire.to_attestation();
        record(
            &format!("attestation_wire_round_trip_{:?}", env),
            back.as_ref().ok() == Some(&att),
        );
    }

    fs::write(out_dir.join("wire_round_trip.txt"), buf)?;
    Ok((pass, fail))
}

// ---------------------------------------------------------------------------
// Sibling parser table: Absent / Available / Malformed-Json /
// Malformed-Wire branches all reachable from
// parse_optional_authority_custody_attestation_sibling_from_json_value.
// ---------------------------------------------------------------------------

fn run_sibling_parse_table(out_dir: &Path) -> std::io::Result<(usize, usize)> {
    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut buf = String::new();

    let mut record = |label: &str, ok: bool, dump: String| {
        if ok {
            pass += 1;
        } else {
            fail += 1;
            eprintln!("[run-191-helper] FAIL sibling parse: {}", label);
        }
        buf.push_str(&format!("{}\tok={}\t{}\n", label, ok, dump));
    };

    let absent = loaded_absent();
    record(
        "absent_no_sibling_field",
        absent.is_absent(),
        format!("{:?}", absent),
    );

    let absent_null = parse_optional_authority_custody_attestation_sibling_from_json_value(
        &serde_json::json!({ AUTHORITY_CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD: null }),
    );
    record(
        "absent_null_sibling",
        absent_null.is_absent(),
        format!("{:?}", absent_null),
    );

    let cand = rotate_candidate(TrustBundleEnvironment::Devnet);
    let att = good_attestation(
        TrustBundleEnvironment::Devnet,
        &cand,
        AuthorityCustodyClass::FixtureLocalKey,
    );
    let avail = loaded_for(&att);
    record(
        "available_well_formed_fixture",
        avail.is_available() && avail.as_attestation() == Some(&att),
        format!("{:?}", avail.is_available()),
    );

    let mj = loaded_malformed_json();
    record(
        "malformed_json_sibling",
        mj.is_malformed() && mj.malformed_error().is_some(),
        format!("{:?}", mj),
    );

    let mw = loaded_malformed_wire_unknown_schema();
    record(
        "malformed_wire_unknown_schema",
        mw.is_malformed() && mw.malformed_error().is_some(),
        format!("{:?}", mw),
    );

    fs::write(out_dir.join("sibling_parse_table.txt"), buf)?;
    Ok((pass, fail))
}

// ---------------------------------------------------------------------------
// Routing helpers table: each of the 7 routing helpers reaches the validator
// and each non-peer-drain helper agrees on a baseline accept.
// ---------------------------------------------------------------------------

fn run_routing_helpers_table(out_dir: &Path) -> std::io::Result<(usize, usize)> {
    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut buf = String::new();

    let env = TrustBundleEnvironment::Devnet;
    let cand = rotate_candidate(env);
    let prior = prior_versioned(env);
    let dom = domain_for(env);
    let ctx = ctx_for(Some(&prior), &cand, &dom, AuthorityCustodyPolicy::FixtureOnly);
    let att = good_attestation(env, &cand, AuthorityCustodyClass::FixtureLocalKey);
    let loaded = loaded_for(&att);

    let mut first_outcome: Option<AuthorityCustodyPayloadCarryingDecisionOutcome> = None;
    for surface in Surface::ALL {
        let outcome = surface.route(&ctx, &loaded);
        let accept = outcome.is_accept();
        let label = surface.label();
        if accept {
            pass += 1;
        } else {
            fail += 1;
            eprintln!("[run-191-helper] FAIL routing_helper_accept: {}", label);
        }
        buf.push_str(&format!(
            "surface\t{}\taccept={}\toutcome={:?}\n",
            label, accept, outcome
        ));
        if first_outcome.is_none() {
            first_outcome = Some(outcome);
        } else if let Some(first) = &first_outcome {
            if first != &surface.route(&ctx, &loaded) {
                fail += 1;
                buf.push_str(&format!(
                    "surface\t{}\tFAIL non-deterministic with first surface\n",
                    label
                ));
            }
        }
    }

    // Peer-driven drain MainNet refusal layered ahead of validator,
    // even with valid DevNet fixture attestation that BINDS MainNet.
    let mn_dom = domain_for(TrustBundleEnvironment::Mainnet);
    let mn_cand = rotate_candidate(TrustBundleEnvironment::Mainnet);
    let mn_ctx = ctx_for(None, &mn_cand, &mn_dom, AuthorityCustodyPolicy::FixtureOnly);
    let mn_outcome =
        route_loaded_authority_custody_attestation_to_peer_driven_drain_callsite_decision(
            &mn_ctx, &loaded,
        );
    let refused = mn_outcome.is_mainnet_peer_driven_apply_refused();
    if refused {
        pass += 1;
    } else {
        fail += 1;
    }
    buf.push_str(&format!(
        "peer_driven_drain_mainnet_refused\trefused={}\toutcome={:?}\n",
        refused, mn_outcome
    ));

    fs::write(out_dir.join("routing_helpers_table.txt"), buf)?;
    Ok((pass, fail))
}

// ---------------------------------------------------------------------------
// Named helpers table: explicit Run 188 / Run 190 grep-verifiable refusal
// helpers.
// ---------------------------------------------------------------------------

fn run_named_helpers_table(out_dir: &Path) -> std::io::Result<(usize, usize)> {
    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut buf = String::new();
    let mut record = |label: &str, ok: bool, dump: String| {
        if ok {
            pass += 1;
        } else {
            fail += 1;
            eprintln!("[run-191-helper] FAIL named helper: {}", label);
        }
        buf.push_str(&format!("{}\tok={}\t{}\n", label, ok, dump));
    };

    record(
        "mainnet_peer_driven_apply_remains_refused_under_custody_payload_carrying_mainnet",
        mainnet_peer_driven_apply_remains_refused_under_custody_payload_carrying(
            TrustBundleEnvironment::Mainnet,
        ),
        "true".to_string(),
    );
    record(
        "mainnet_peer_driven_apply_remains_refused_under_custody_payload_carrying_devnet",
        !mainnet_peer_driven_apply_remains_refused_under_custody_payload_carrying(
            TrustBundleEnvironment::Devnet,
        ),
        "false".to_string(),
    );
    record(
        "mainnet_peer_driven_apply_remains_refused_under_custody_payload_carrying_testnet",
        !mainnet_peer_driven_apply_remains_refused_under_custody_payload_carrying(
            TrustBundleEnvironment::Testnet,
        ),
        "false".to_string(),
    );
    record(
        "mainnet_peer_driven_apply_remains_refused_under_custody_boundary_mainnet",
        mainnet_peer_driven_apply_remains_refused_under_custody_boundary(
            TrustBundleEnvironment::Mainnet,
        ),
        "true".to_string(),
    );
    record(
        "peer_majority_cannot_satisfy_custody",
        peer_majority_cannot_satisfy_custody(),
        "true".to_string(),
    );
    record(
        "local_operator_config_alone_cannot_satisfy_mainnet_production_custody",
        local_operator_config_alone_cannot_satisfy_mainnet_production_custody(),
        "true".to_string(),
    );

    fs::write(out_dir.join("named_helpers_table.txt"), buf)?;
    Ok((pass, fail))
}

// ---------------------------------------------------------------------------
// No-mutation evidence: a rejecting routing pass leaves every input bit-equal.
// ---------------------------------------------------------------------------

fn run_no_mutation_evidence(out_dir: &Path) -> std::io::Result<(usize, usize)> {
    let env = TrustBundleEnvironment::Devnet;
    let cand = rotate_candidate(env);
    let cand_before = cand.clone();
    let prior = prior_versioned(env);
    let prior_before = prior.clone();
    let dom = domain_for(env);
    let dom_before = dom.clone();
    let att = good_attestation(env, &cand, AuthorityCustodyClass::Kms);
    let att_before = att.clone();
    let loaded = loaded_for(&att);
    let loaded_before = loaded.clone();
    let ctx = ctx_for(
        Some(&prior),
        &cand,
        &dom,
        AuthorityCustodyPolicy::ProductionCustodyRequired,
    );

    // Run every routing surface; capture outcomes.
    let mut outcomes = Vec::new();
    for surface in Surface::ALL {
        outcomes.push((surface.label(), surface.route(&ctx, &loaded)));
    }

    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut buf = String::new();
    let mut record = |label: &str, ok: bool| {
        if ok {
            pass += 1;
        } else {
            fail += 1;
            eprintln!("[run-191-helper] FAIL no-mutation invariant: {}", label);
        }
        buf.push_str(&format!("{}\tok={}\n", label, ok));
    };

    let all_reject = outcomes.iter().all(|(_, o)| o.is_reject());
    record("all_surfaces_reject_kms_under_production_required", all_reject);
    record("candidate_unchanged", cand == cand_before);
    record("prior_unchanged", prior == prior_before);
    record("trust_domain_unchanged", dom == dom_before);
    record("attestation_unchanged", att == att_before);
    record("loaded_status_unchanged", loaded == loaded_before);

    for (label, outcome) in &outcomes {
        buf.push_str(&format!("surface_outcome\t{}\t{:?}\n", label, outcome));
    }
    fs::write(out_dir.join("no_mutation_evidence.txt"), buf)?;
    Ok((pass, fail))
}

// ---------------------------------------------------------------------------
// Determinism: 32 dispatches of the accepted DevNet fixture scenario yield
// identical Accept outcome on every routing surface.
// ---------------------------------------------------------------------------

fn run_determinism_check(out_dir: &Path) -> std::io::Result<(usize, usize)> {
    let env = TrustBundleEnvironment::Devnet;
    let cand = rotate_candidate(env);
    let prior = prior_versioned(env);
    let dom = domain_for(env);
    let ctx = ctx_for(Some(&prior), &cand, &dom, AuthorityCustodyPolicy::FixtureOnly);
    let att = good_attestation(env, &cand, AuthorityCustodyClass::FixtureLocalKey);
    let loaded = loaded_for(&att);

    let mut buf = String::new();
    let mut pass = 0usize;
    let mut fail = 0usize;

    for surface in Surface::ALL {
        let mut samples = Vec::new();
        for _ in 0..32 {
            samples.push(surface.route(&ctx, &loaded));
        }
        let first = samples[0].clone();
        let all_eq = samples.iter().all(|o| *o == first);
        let first_accept = first.is_accept();
        let ok = all_eq && first_accept;
        if ok {
            pass += 1;
        } else {
            fail += 1;
            eprintln!(
                "[run-191-helper] FAIL determinism on {}: all_eq={} first_accept={}",
                surface.label(),
                all_eq,
                first_accept
            );
        }
        buf.push_str(&format!(
            "surface\t{}\tsamples=32\tall_equal={}\tfirst_accept={}\tsample={:?}\n",
            surface.label(),
            all_eq,
            first_accept,
            first
        ));
    }

    fs::write(out_dir.join("determinism_evidence.txt"), buf)?;
    Ok((pass, fail))
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
    let mut args = env::args().skip(1);
    let out_dir: PathBuf = match args.next() {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!(
                "usage: run_191_authority_custody_payload_release_binary_helper <OUT_DIR>"
            );
            std::process::exit(2);
        }
    };
    fs::create_dir_all(&out_dir).expect("create out_dir");

    let mut manifest = String::new();
    let mut expected_buf = String::new();
    let mut actual_buf = String::new();

    let (s_pass, s_fail) = run_routing_corpus(
        &out_dir,
        &mut manifest,
        &mut expected_buf,
        &mut actual_buf,
    )
    .expect("routing corpus");
    let (w_pass, w_fail) = run_wire_round_trip(&out_dir).expect("wire round trip");
    let (p_pass, p_fail) = run_sibling_parse_table(&out_dir).expect("sibling parse table");
    let (r_pass, r_fail) = run_routing_helpers_table(&out_dir).expect("routing helpers table");
    let (h_pass, h_fail) = run_named_helpers_table(&out_dir).expect("named helpers table");
    let (n_pass, n_fail) = run_no_mutation_evidence(&out_dir).expect("no mutation evidence");
    let (d_pass, d_fail) = run_determinism_check(&out_dir).expect("determinism check");

    fs::write(out_dir.join("manifest.txt"), &manifest).expect("write manifest");
    fs::write(out_dir.join("expected_outcomes.txt"), &expected_buf).expect("write expected");
    fs::write(out_dir.join("actual_outcomes.txt"), &actual_buf).expect("write actual");

    let total_pass = s_pass + w_pass + p_pass + r_pass + h_pass + n_pass + d_pass;
    let total_fail = s_fail + w_fail + p_fail + r_fail + h_fail + n_fail + d_fail;
    let verdict = if total_fail == 0 { "PASS" } else { "FAIL" };

    let mut summary = fs::File::create(out_dir.join("helper_summary.txt"))
        .expect("create helper_summary.txt");
    writeln!(
        summary,
        "Run 191 helper - release-mode authority-custody payload-carrying corpus"
    )
    .unwrap();
    writeln!(summary, "verdict: {}", verdict).unwrap();
    writeln!(
        summary,
        "total_pass: {}\ntotal_fail: {}",
        total_pass, total_fail
    )
    .unwrap();
    writeln!(summary, "scenarios_pass: {}\nscenarios_fail: {}", s_pass, s_fail).unwrap();
    writeln!(summary, "wire_pass: {}\nwire_fail: {}", w_pass, w_fail).unwrap();
    writeln!(summary, "sibling_pass: {}\nsibling_fail: {}", p_pass, p_fail).unwrap();
    writeln!(summary, "routing_pass: {}\nrouting_fail: {}", r_pass, r_fail).unwrap();
    writeln!(
        summary,
        "named_helpers_pass: {}\nnamed_helpers_fail: {}",
        h_pass, h_fail
    )
    .unwrap();
    writeln!(
        summary,
        "no_mutation_pass: {}\nno_mutation_fail: {}",
        n_pass, n_fail
    )
    .unwrap();
    writeln!(
        summary,
        "determinism_pass: {}\ndeterminism_fail: {}",
        d_pass, d_fail
    )
    .unwrap();
    writeln!(summary, "production_symbols_exercised:").unwrap();
    for s in &[
        "qbind_node::pqc_authority_custody_payload_carrying::AuthorityCustodyAttestationWire",
        "qbind_node::pqc_authority_custody_payload_carrying::AuthorityCustodyClassWire",
        "qbind_node::pqc_authority_custody_payload_carrying::GovernanceAuthorityClassWire",
        "qbind_node::pqc_authority_custody_payload_carrying::AuthorityCustodyLoadStatus",
        "qbind_node::pqc_authority_custody_payload_carrying::AuthorityCustodyCallsiteContext",
        "qbind_node::pqc_authority_custody_payload_carrying::AuthorityCustodyPayloadCarryingDecisionOutcome",
        "qbind_node::pqc_authority_custody_payload_carrying::parse_optional_authority_custody_attestation_sibling_from_json_value",
        "qbind_node::pqc_authority_custody_payload_carrying::callsite_context_for_authority_custody",
        "qbind_node::pqc_authority_custody_payload_carrying::route_loaded_authority_custody_attestation_to_reload_check_callsite_decision",
        "qbind_node::pqc_authority_custody_payload_carrying::route_loaded_authority_custody_attestation_to_reload_apply_callsite_decision",
        "qbind_node::pqc_authority_custody_payload_carrying::route_loaded_authority_custody_attestation_to_startup_p2p_trust_bundle_callsite_decision",
        "qbind_node::pqc_authority_custody_payload_carrying::route_loaded_authority_custody_attestation_to_sighup_callsite_decision",
        "qbind_node::pqc_authority_custody_payload_carrying::route_loaded_authority_custody_attestation_to_local_peer_candidate_check_callsite_decision",
        "qbind_node::pqc_authority_custody_payload_carrying::route_loaded_authority_custody_attestation_to_live_inbound_0x05_callsite_decision",
        "qbind_node::pqc_authority_custody_payload_carrying::route_loaded_authority_custody_attestation_to_peer_driven_drain_callsite_decision",
        "qbind_node::pqc_authority_custody_payload_carrying::mainnet_peer_driven_apply_remains_refused_under_custody_payload_carrying",
        "qbind_node::pqc_authority_custody::validate_authority_custody_attestation",
        "qbind_node::pqc_authority_custody::validate_lifecycle_governance_and_custody",
        "qbind_node::pqc_authority_custody::mainnet_peer_driven_apply_remains_refused_under_custody_boundary",
        "qbind_node::pqc_authority_custody::peer_majority_cannot_satisfy_custody",
        "qbind_node::pqc_authority_custody::local_operator_config_alone_cannot_satisfy_mainnet_production_custody",
    ] {
        writeln!(summary, "  - {}", s).unwrap();
    }
    writeln!(summary, "honest_limits:").unwrap();
    for line in &[
        "default AuthorityCustodyPolicy::Disabled fail-closed on every surface",
        "no real KMS / HSM / cloud-KMS / PKCS#11 / remote-signer backend wired in Run 191",
        "RemoteSigner / Kms / Hsm placeholders fail closed at the Run 188 validator",
        "fixture / local-operator custody remains DevNet/TestNet evidence-only",
        "fixture / local-operator custody refused on MainNet ahead of policy gate",
        "MainNet peer-driven apply remains refused regardless of custody contents",
        "no schema/wire/metric drift beyond Run 190 additive optional custody sibling",
        "no marker write; no sequence write; no live trust swap; no Run 070 call",
        "full C4 remains open; C5 remains open",
    ] {
        writeln!(summary, "  {}", line).unwrap();
    }

    if total_fail != 0 {
        std::process::exit(1);
    }
}