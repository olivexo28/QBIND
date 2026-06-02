//! Run 148 (C4 piece: peer-driven trust-bundle apply, **source/test-only**
//! peer-driven live apply controller, DevNet/TestNet-only, disabled-by-default,
//! local-policy gated, strictly reusing the existing Run 070 apply contract).
//!
//! # Strict scope (matches `task/RUN_148_TASK.txt`)
//!
//! - **Source/test wiring only.** No release-binary peer-driven apply
//!   evidence is claimed in this run; release-binary DevNet/TestNet
//!   peer-driven apply evidence is deferred to Run 149.
//! - **DevNet / TestNet only.** MainNet is refused unconditionally even
//!   with the policy fully enabled. There is no MainNet bypass flag.
//! - **Disabled by default.** [`PeerDrivenApplyPolicy::default`] returns
//!   `enabled = false` and `allow_devnet = allow_testnet =
//!   allow_mainnet = false`.
//! - **No governance / KMS / HSM / signing-key lifecycle.**
//! - **No new wire format.** Live inbound `0x05` envelope and the Run
//!   146 staging hook are unchanged.
//! - **No trust-bundle / ratification-sidecar / authority-marker /
//!   sequence-file schema change.**
//! - **No automatic apply on validation alone.** Validation-only
//!   acceptance is **not** an apply trigger; an explicit, separate
//!   local peer-driven apply policy decision must be evaluated.
//! - **No apply of unstaged, invalid, or expired staged candidates.**
//!   TTL is enforced at apply time, not only at staging time.
//! - **Does not weaken** any existing local reload-apply, SIGHUP,
//!   startup, snapshot/restore, validation-only, staging, or
//!   propagation behaviour. The controller is a separate decision
//!   gated by [`PeerDrivenApplyPolicy`].
//!
//! # Required pipeline (Run 148 task §Design requirement)
//!
//! 1. live inbound `0x05` candidate received (Run 142/143);
//! 2. existing validation-only path accepts (Run 142);
//! 3. Run 146 staging hook stages candidate (Run 145 queue, Run 146 wire);
//! 4. explicit local peer-driven apply policy is evaluated (this module);
//! 5. staged candidate is revalidated or validated candidate material is
//!    proven fresh (this module);
//! 6. existing Run 070 apply contract is invoked
//!    ([`crate::pqc_trust_reload::apply_validated_candidate_with_previous`]);
//! 7. v2 authority marker is persisted **only after** `commit_sequence`
//!    succeeds (Run 134/138 discipline);
//! 8. failure semantics mirror Run 070 / Run 134 / Run 138.
//!
//! # Reuse of existing apply contract
//!
//! The controller does **not** introduce a new apply algorithm. It calls
//! [`crate::pqc_trust_reload::apply_validated_candidate_with_previous`] with
//! [`crate::pqc_trust_reload::ApplyMode::ApplyLive`] and the caller-supplied
//! [`crate::pqc_trust_reload::LiveTrustApplyContext`] (in production: the
//! Run 073 `ProductionLiveTrustApplyContext`). This reuses the validate →
//! snapshot previous → swap → evict_sessions → commit_sequence ordering and
//! the rollback/fatal semantics defined in `task/RUN_070_TASK.txt`.
//!
//! The controller **never** directly mutates [`crate::pqc_live_trust::LivePqcTrustState`],
//! `pqc_trust_bundle_sequence.json`, or `pqc_authority_state.json`; every
//! mutation goes through the existing apply pipeline and the existing
//! [`crate::pqc_authority_marker_acceptance::persist_accepted_v2_marker_after_commit_boundary`]
//! helper.
//!
//! # v2 marker post-commit discipline
//!
//! When the policy requires a v2 ratification (`require_v2_ratification = true`),
//! the controller takes a [`V2MarkerCoordinator`] whose contract mirrors
//! Run 134/138:
//!
//! - `decide_pre_apply` runs **before** the Run 070 apply call. A
//!   conflict outcome (lower sequence, same-sequence different digest,
//!   wrong-domain, malformed, etc.) returns
//!   [`PeerDrivenApplyOutcome::CandidateMarkerConflict`] and the apply
//!   pipeline is **not** entered. No live state mutation, no sequence
//!   write, no marker write.
//! - `persist_after_commit` runs **only** after a successful
//!   `commit_sequence`. A persist failure here is fatal/operator-
//!   actionable per Run 134/138 — the controller surfaces
//!   [`PeerDrivenApplyOutcome::MarkerPersistFailedAfterCommit`] and the
//!   operator must treat the node as inconsistent until the marker is
//!   reconciled offline (the on-disk sequence has already advanced).
//!
//! # MainNet refusal
//!
//! MainNet refuses unconditionally with
//! [`PeerDrivenApplyOutcome::RefusedMainNet`]. The refusal:
//!
//! - is typed (not a string log line),
//! - precedes any staged-candidate lookup, any Run 070 apply call, any
//!   marker check, and any persistence touch,
//! - is intentionally not influenced by `allow_mainnet` — that field is
//!   kept on the policy struct so a future governance/KMS-HSM gate can
//!   be wired without an API churn, but Run 148 ignores it.

use std::time::Duration;

use qbind_types::NetworkEnvironment;

use crate::pqc_peer_candidate_staging::{
    PeerCandidateStagingQueue, StagedPeerCandidate,
};
use crate::pqc_trust_bundle::TrustBundleEnvironment;
use crate::pqc_trust_reload::{
    apply_validated_candidate_with_previous, ApplyMode, AppliedCandidate, LiveTrustApplyContext,
    ReloadApplyError, ReloadCheckInputs,
};

/// Default freshness ceiling for a staged candidate before peer-driven
/// apply will refuse it. Picked equal to
/// [`crate::pqc_peer_candidate_staging::DEFAULT_TTL_SECS`] so the apply
/// policy never accepts a candidate the staging queue would have
/// already swept.
pub const DEFAULT_MAX_CANDIDATE_AGE_SECS: u64 = 300;

/// Policy that decides whether — and on which environment — the
/// peer-driven apply controller is allowed to invoke the existing
/// Run 070 apply contract for a staged, validation-accepted peer
/// candidate.
///
/// **Disabled by default on every environment.** MainNet is refused
/// unconditionally regardless of `allow_mainnet` because Run 148
/// explicitly does not introduce any MainNet bypass (Run 148 §5).
#[derive(Debug, Clone)]
pub struct PeerDrivenApplyPolicy {
    /// Master enable switch. If `false`, every call to
    /// [`try_apply_staged_peer_candidate`] returns
    /// [`PeerDrivenApplyOutcome::Disabled`].
    pub enabled: bool,
    /// Resolved runtime environment of the receiving node.
    pub environment: NetworkEnvironment,
    /// Permit peer-driven apply on DevNet when `enabled == true`.
    pub allow_devnet: bool,
    /// Permit peer-driven apply on TestNet when `enabled == true` AND
    /// the caller has independently verified v2 ratification through
    /// the existing Run 130 verifier and the Run 132/134/142 marker
    /// validation-only check before staging.
    pub allow_testnet: bool,
    /// Permit peer-driven apply on MainNet. **IGNORED for now** —
    /// Run 148 MainNet peer-driven apply is refused unconditionally
    /// regardless of `allow_mainnet`. Kept on the policy struct so a
    /// future governance / KMS-HSM gate can flip it behind a separate
    /// authority check without API churn.
    pub allow_mainnet: bool,
    /// If `true`, only candidates already present in the staging queue
    /// can reach the apply path. Default `true` — Run 148 does not
    /// permit "validated but unstaged" candidates to apply.
    pub require_staged_candidate: bool,
    /// If `true`, the controller requires a [`V2MarkerCoordinator`] to
    /// run the pre-apply marker decision and post-commit marker
    /// persist. Default `true` — Run 148 does not permit a v1-only
    /// peer-driven apply.
    pub require_v2_ratification: bool,
    /// Maximum age (wall-clock seconds) of a staged candidate at the
    /// moment of apply. Older candidates are refused with
    /// [`PeerDrivenApplyOutcome::CandidateExpired`].
    pub max_candidate_age_secs: u64,
}

impl Default for PeerDrivenApplyPolicy {
    /// **Disabled-by-default on every environment.**
    fn default() -> Self {
        Self {
            enabled: false,
            environment: NetworkEnvironment::Devnet,
            allow_devnet: false,
            allow_testnet: false,
            allow_mainnet: false,
            require_staged_candidate: true,
            require_v2_ratification: true,
            max_candidate_age_secs: DEFAULT_MAX_CANDIDATE_AGE_SECS,
        }
    }
}

impl PeerDrivenApplyPolicy {
    /// Convenience constructor for a DevNet-only enabled policy with
    /// default safety bounds (require_staged_candidate = true,
    /// require_v2_ratification = true).
    pub fn devnet_enabled() -> Self {
        Self {
            enabled: true,
            environment: NetworkEnvironment::Devnet,
            allow_devnet: true,
            allow_testnet: false,
            allow_mainnet: false,
            ..Self::default()
        }
    }

    /// Convenience constructor for a TestNet-only enabled policy.
    /// Callers are responsible for ensuring the upstream v2
    /// ratification verifier already accepted the candidate.
    pub fn testnet_enabled() -> Self {
        Self {
            enabled: true,
            environment: NetworkEnvironment::Testnet,
            allow_devnet: false,
            allow_testnet: true,
            allow_mainnet: false,
            ..Self::default()
        }
    }

    /// Convenience constructor for the (currently always-refused)
    /// MainNet attempt. The returned policy claims `enabled = true`
    /// and `allow_mainnet = true`, but [`try_apply_staged_peer_candidate`]
    /// **still refuses** because Run 148 enforces an unconditional
    /// MainNet block.
    pub fn mainnet_attempted() -> Self {
        Self {
            enabled: true,
            environment: NetworkEnvironment::Mainnet,
            allow_devnet: false,
            allow_testnet: false,
            allow_mainnet: true,
            ..Self::default()
        }
    }
}

/// Trait the controller uses to drive the Run 134/138 v2 marker
/// pre-apply decision and post-commit persistence.
///
/// Production callers wire this to
/// [`crate::pqc_authority_marker_acceptance::decide_marker_acceptance_v2`]
/// + [`crate::pqc_authority_marker_acceptance::persist_accepted_v2_marker_after_commit_boundary`].
/// Tests use a fake that lets each scenario decide the pre/post outcomes
/// independently so the R3/R4/R12 matrix can be exercised without
/// constructing real ratification objects.
///
/// **Invariants the implementation MUST uphold (matches Run 134/138):**
///
/// - `decide_pre_apply` is allowed to read the existing marker file but
///   MUST NOT write it.
/// - `persist_after_commit` is the only path that writes the marker
///   file, and the controller MUST call it only after a successful
///   `commit_sequence`.
pub trait V2MarkerCoordinator {
    /// Pre-apply marker decision/check. Returns `Ok(())` for accept
    /// outcomes (first-write, idempotent, higher-sequence, v2-after-v1
    /// migration); returns `Err(reason)` for refusals (lower sequence,
    /// same-sequence different digest, wrong domain, etc.).
    ///
    /// Called **before** the controller enters the Run 070 apply
    /// pipeline. On `Err`, the controller short-circuits with
    /// [`PeerDrivenApplyOutcome::CandidateMarkerConflict`] and does NOT
    /// touch live trust state, the sequence file, or the marker file.
    fn decide_pre_apply(&mut self) -> Result<(), String>;

    /// Post-commit marker persist. Called **only** after
    /// `commit_sequence` succeeded in the Run 070 pipeline.
    ///
    /// On `Err`, the controller surfaces
    /// [`PeerDrivenApplyOutcome::MarkerPersistFailedAfterCommit`]: the
    /// trust-bundle sequence has already advanced, so the on-disk
    /// marker is stale-by-one; the operator MUST be notified and
    /// reconcile offline. **This is the fatal/operator-actionable
    /// branch.**
    fn persist_after_commit(&mut self) -> Result<(), String>;
}

/// No-op v2 marker coordinator. Useful only for tests that disable the
/// `require_v2_ratification` flag (and therefore never invoke the
/// coordinator). Production must never pass `None` to a
/// `require_v2_ratification = true` policy; the controller fails
/// closed via [`PeerDrivenApplyOutcome::ApplyRejected`] in that case
/// instead of silently skipping the marker discipline.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoV2MarkerCoordinator;

impl V2MarkerCoordinator for NoV2MarkerCoordinator {
    fn decide_pre_apply(&mut self) -> Result<(), String> {
        Ok(())
    }
    fn persist_after_commit(&mut self) -> Result<(), String> {
        Ok(())
    }
}

/// Run 152 — **production-capable** [`V2MarkerCoordinator`] for the
/// peer-driven apply path. Wires the existing Run 134/136/138/150 v2
/// marker decision discipline
/// ([`crate::pqc_authority_marker_acceptance::decide_marker_acceptance_v2`]
/// + [`crate::pqc_authority_marker_acceptance::persist_accepted_v2_marker_after_commit_boundary`])
/// into the Run 148 controller's pre-apply / post-commit boundary so a
/// real `target/release/qbind-node` drain can run the same fail-closed
/// marker logic the local reload-apply (Run 134), SIGHUP (Run 138), and
/// snapshot/restore (Run 140) paths use.
///
/// **Invariants (matching Run 134/138 and the [`V2MarkerCoordinator`]
/// trait contract):**
///
/// - [`Self::decide_pre_apply`] runs `decide_marker_acceptance_v2`,
///   which performs **no** disk write. It re-checks
///   environment / chain_id / genesis_hash / authority-root binding,
///   refuses a lower `authority_domain_sequence`, refuses a
///   same-sequence different-digest equivocation, refuses a wrong
///   trust domain, and refuses a corrupted / unsupported persisted
///   marker. On any refusal the controller short-circuits with
///   [`PeerDrivenApplyOutcome::CandidateMarkerConflict`] **before** the
///   Run 070 apply pipeline is entered — no sequence write, no swap, no
///   marker write.
/// - The accepted decision is held in `decision` and is the only thing
///   [`Self::persist_after_commit`] writes — and only after the Run 070
///   `commit_sequence` boundary has succeeded. A persist failure there
///   is surfaced as
///   [`PeerDrivenApplyOutcome::MarkerPersistFailedAfterCommit`]
///   (fatal / operator-actionable) per Run 134 §PersistFailure.
/// - The coordinator never mutates [`crate::pqc_live_trust::LivePqcTrustState`],
///   never evicts sessions, and never calls Run 070 directly.
///
/// The coordinator owns the verified v2 ratification + verifier output
/// (`ratification` / `ratified`) because
/// [`crate::pqc_authority_marker_acceptance::MarkerAcceptanceV2Inputs`]
/// borrows them; production callers obtain those from the existing
/// Run 130 verifier output captured during validation-only acceptance.
pub struct ProductionV2MarkerCoordinator {
    marker_path: std::path::PathBuf,
    runtime_env: NetworkEnvironment,
    runtime_chain_id: qbind_types::ChainId,
    runtime_genesis_hash_hex: String,
    ratification: qbind_ledger::BundleSigningRatificationV2,
    ratified: qbind_ledger::RatifiedBundleSigningKeyV2,
    update_source: crate::pqc_authority_state::AuthorityStateUpdateSource,
    updated_at_unix_secs: u64,
    /// Accepted pre-apply decision, populated by `decide_pre_apply`.
    /// Persisted (when `should_persist`) by `persist_after_commit`.
    decision: Option<crate::pqc_authority_marker_acceptance::MarkerAcceptDecisionV2>,
    /// Run 169 — typed Run 167 governance-proof load status for the
    /// peer-driven candidate. Defaults to
    /// [`crate::pqc_governance_proof_wire::GovernanceProofLoadStatus::Absent`]
    /// (preserving every Run 148/150/152/153 invariant when the peer
    /// candidate envelope carries no Run 167 sibling). Populated via
    /// [`Self::with_governance_proof_carrier`] when an additive
    /// governance-proof carrier is available out-of-band (DevNet/TestNet
    /// fixtures or the Run 170 release-binary path).
    governance_proof_load: crate::pqc_governance_proof_wire::GovernanceProofLoadStatus,
    /// Run 169 — governance proof policy. Defaults to
    /// [`crate::pqc_governance_authority::GovernanceProofPolicy::NotRequired`]
    /// so the existing Run 148/150/152/153 peer-driven apply test
    /// matrix (which has no Run 167 fixtures) remains green.
    governance_policy: crate::pqc_governance_authority::GovernanceProofPolicy,
}

impl ProductionV2MarkerCoordinator {
    /// Construct a production coordinator for the supplied trust domain
    /// and verified v2 ratification. `update_source` is audit-only
    /// (excluded from the marker security digest); peer-driven apply
    /// reuses the Run 070 reload-apply contract, so
    /// [`crate::pqc_authority_state::AuthorityStateUpdateSource::ReloadApply`]
    /// is the honest default.
    ///
    /// Run 169 — the coordinator defaults to
    /// [`crate::pqc_governance_proof_wire::GovernanceProofLoadStatus::Absent`]
    /// under
    /// [`crate::pqc_governance_authority::GovernanceProofPolicy::NotRequired`].
    /// Use [`Self::with_governance_proof_carrier`] (additive builder) to
    /// attach a typed Run 167 governance-proof load status and policy.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        marker_path: std::path::PathBuf,
        runtime_env: NetworkEnvironment,
        runtime_chain_id: qbind_types::ChainId,
        runtime_genesis_hash_hex: String,
        ratification: qbind_ledger::BundleSigningRatificationV2,
        ratified: qbind_ledger::RatifiedBundleSigningKeyV2,
        update_source: crate::pqc_authority_state::AuthorityStateUpdateSource,
        updated_at_unix_secs: u64,
    ) -> Self {
        Self {
            marker_path,
            runtime_env,
            runtime_chain_id,
            runtime_genesis_hash_hex,
            ratification,
            ratified,
            update_source,
            updated_at_unix_secs,
            decision: None,
            governance_proof_load:
                crate::pqc_governance_proof_wire::GovernanceProofLoadStatus::Absent,
            governance_policy:
                crate::pqc_governance_authority::GovernanceProofPolicy::NotRequired,
        }
    }

    /// Run 169 — additive builder that attaches a typed Run 167
    /// [`crate::pqc_governance_proof_wire::GovernanceProofLoadStatus`]
    /// and a Run 165
    /// [`crate::pqc_governance_authority::GovernanceProofPolicy`] to
    /// the coordinator so [`Self::decide_pre_apply`] routes through the
    /// Run 169 governance-proof surface shim and the Run 165
    /// governance gate sees the actual loader output.
    ///
    /// Default behaviour (without this builder) is preserved bit-for-bit
    /// — `Absent` + `NotRequired` = `NotRequiredNoProof` accept at the
    /// gate, identical to Run 165's documented baseline.
    ///
    /// Non-MainNet-enabling: a valid governance proof here does **not**
    /// enable MainNet peer-driven apply. The existing environment gate
    /// upstream of the coordinator owns that refusal and is unchanged
    /// by Run 169.
    pub fn with_governance_proof_carrier(
        mut self,
        governance_proof_load: crate::pqc_governance_proof_wire::GovernanceProofLoadStatus,
        governance_policy: crate::pqc_governance_authority::GovernanceProofPolicy,
    ) -> Self {
        self.governance_proof_load = governance_proof_load;
        self.governance_policy = governance_policy;
        self
    }

    /// Audit-only accessor for the accepted pre-apply decision (if any).
    /// Returns `None` before `decide_pre_apply` has accepted.
    pub fn accepted_decision(
        &self,
    ) -> Option<&crate::pqc_authority_marker_acceptance::MarkerAcceptDecisionV2> {
        self.decision.as_ref()
    }
}

impl V2MarkerCoordinator for ProductionV2MarkerCoordinator {
    fn decide_pre_apply(&mut self) -> Result<(), String> {
        let inputs = crate::pqc_authority_marker_acceptance::MarkerAcceptanceV2Inputs {
            marker_path: &self.marker_path,
            runtime_env: self.runtime_env,
            runtime_chain_id: self.runtime_chain_id,
            runtime_genesis_hash_hex: &self.runtime_genesis_hash_hex,
            ratification: &self.ratification,
            ratified: &self.ratified,
            update_source: self.update_source,
            updated_at_unix_secs: self.updated_at_unix_secs,
        };
        // Run 169: route the peer-driven drain pre-apply decision
        // through the Run 169 governance-proof surface shim so the
        // typed Run 167 `GovernanceProofLoadStatus` attached via
        // `with_governance_proof_carrier` (or the `Absent` default)
        // reaches the Run 165 governance gate. The fixture verifier
        // is the source/test issuer-signature verifier — release-
        // binary production-surface proof-carrying evidence is
        // deferred to Run 170 (a real PQC verifier replaces this hook
        // then). MainNet peer-driven apply remains refused by the
        // existing upstream environment gate regardless of governance
        // proof.
        let verifier =
            crate::pqc_governance_authority::fixture_issuer_signature_verifier();
        match crate::pqc_governance_proof_surface::preflight_v2_marker_decision_with_governance_proof_load(
            inputs,
            self.governance_policy,
            &self.governance_proof_load,
            &verifier,
        ) {
            Ok(decision) => {
                self.decision = Some(decision);
                Ok(())
            }
            Err(e) => {
                // Fail closed: clear any stale decision so a later
                // `persist_after_commit` can never write a marker for a
                // refused candidate.
                self.decision = None;
                Err(e.to_string())
            }
        }
    }

    fn persist_after_commit(&mut self) -> Result<(), String> {
        // Defence-in-depth: persistence is only ever reachable after a
        // successful `decide_pre_apply`; never fabricate a write.
        let decision = self.decision.as_ref().ok_or_else(|| {
            "Run 152: persist_after_commit invoked without an accepted \
             pre-apply v2 marker decision (fail closed; no marker write)"
                .to_string()
        })?;
        crate::pqc_authority_marker_acceptance::persist_accepted_v2_marker_after_commit_boundary(
            decision,
        )
        .map_err(|e| e.to_string())
    }
}

/// Runtime trust domain (environment + chain id encoded as 16 lowercase
/// hex chars, matching [`crate::pqc_trust_sequence::chain_id_hex`]).
/// Used to fail-closed any staged candidate whose declared environment
/// or chain id does not match the receiving node's runtime domain.
///
/// The chain id is carried in hex form because the staging queue itself
/// records `chain_id_hex` (Run 145 design) rather than the typed
/// [`qbind_types::ChainId`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerDrivenApplyRuntimeDomain {
    pub environment: NetworkEnvironment,
    pub chain_id_hex: String,
}

impl PeerDrivenApplyRuntimeDomain {
    pub fn new(environment: NetworkEnvironment, chain_id_hex: String) -> Self {
        Self {
            environment,
            chain_id_hex,
        }
    }

    fn trust_env(&self) -> TrustBundleEnvironment {
        TrustBundleEnvironment::from_runtime(self.environment)
    }
}

/// Caller-supplied bundle of the inputs the Run 070 apply pipeline
/// consumes. Split out from the policy so the policy stays a pure
/// configuration record.
///
/// `inputs` is built by the caller from the staged candidate's on-disk
/// bundle file path + the runtime environment / chain id / signing
/// keys, matching the existing Run 070 invocation pattern (see
/// `crates/qbind-node/src/main.rs` `apply_validated_candidate_with_previous`
/// call sites and `tests/run_070_pqc_trust_bundle_reload_apply_tests.rs`).
pub struct PeerDrivenApplyInvocation<'a> {
    /// Run 070 inputs. The candidate path MUST be the staged
    /// candidate's already-written bundle file (Run 146/147 binary
    /// hook is responsible for persisting the validated bundle bytes
    /// to a path before invoking this controller).
    pub inputs: ReloadCheckInputs<'a>,
    /// Production [`LiveTrustApplyContext`]. In production: the
    /// Run 073 `ProductionLiveTrustApplyContext`. In tests: the same
    /// `FakeLiveTrustApplyContext` used by the Run 070 tests so the
    /// strict snapshot → swap → evict → commit ordering is observable.
    pub live_apply_ctx: &'a mut dyn LiveTrustApplyContext,
    /// Operator-supplied previous fingerprint prefix (Run 070 operator-
    /// log metadata).
    pub previous_fingerprint_prefix: String,
    /// Operator-supplied previous accepted sequence.
    pub previous_sequence: Option<u64>,
}

/// Run 148 outcome of [`try_apply_staged_peer_candidate`]. Every variant
/// — including the success paths — is **explicitly typed** so the
/// caller can route operator logs / metrics without scraping strings.
///
/// The refusal variants MUST be honoured by the caller as
/// non-mutating: when the controller returns any variant other than
/// [`Self::ApplySucceeded`] / [`Self::MarkerPersistedAfterCommit`] /
/// [`Self::ApplyRollbackSucceeded`] / [`Self::ApplyFatalRollbackFailed`],
/// **no** live trust state mutation, **no** sequence write, **no**
/// authority marker write, **no** session eviction has happened (the
/// controller never invoked the Run 070 apply pipeline on those
/// branches, or the apply pipeline itself fail-closed before any
/// mutation).
#[derive(Debug)]
pub enum PeerDrivenApplyOutcome {
    /// `PeerDrivenApplyPolicy::enabled == false`. Default outcome.
    /// No staging-queue lookup, no marker touch, no apply call.
    Disabled,
    /// Receiving node is on MainNet. Refused unconditionally regardless
    /// of `allow_mainnet`. No staging-queue lookup, no marker touch,
    /// no apply call.
    RefusedMainNet,
    /// `PeerDrivenApplyPolicy::allow_devnet / allow_testnet` is
    /// `false` for the running environment. No staging-queue lookup,
    /// no marker touch, no apply call.
    RefusedEnvironmentPolicy,
    /// `require_staged_candidate == true` (default) and no staged
    /// candidate matches the supplied id. No marker touch, no apply
    /// call.
    CandidateNotFound,
    /// Staged candidate exists but exceeds
    /// `policy.max_candidate_age_secs` at `now_unix_secs`. No marker
    /// touch, no apply call.
    CandidateExpired {
        staged_at_unix_secs: u64,
        age_secs: u64,
        max_age_secs: u64,
    },
    /// Caller passed a candidate id but the staged entry recorded
    /// `signature_verified == false` (the upstream Run 142 validator
    /// did not verify the v2 ratification signature). No marker touch,
    /// no apply call.
    CandidateNotValidated,
    /// Staged candidate declares a different environment or chain id
    /// than the runtime domain. No marker touch, no apply call.
    CandidateWrongDomain {
        candidate_environment: TrustBundleEnvironment,
        candidate_chain_id_hex: String,
        runtime_environment: NetworkEnvironment,
        runtime_chain_id_hex: String,
    },
    /// Pre-apply v2 marker check refused the candidate (lower
    /// sequence, same-sequence different digest, wrong domain on the
    /// marker, etc.). No apply call, no marker write, no live state
    /// mutation.
    CandidateMarkerConflict {
        reason: String,
    },
    /// Run 070 apply pipeline succeeded. **No marker persist required**
    /// (policy `require_v2_ratification = false`, or coordinator
    /// reported the no-op idempotent case). Returned together with the
    /// [`AppliedCandidate`] for operator-log purposes.
    ApplySucceeded {
        applied: AppliedCandidate,
    },
    /// Run 070 apply pipeline refused the candidate during validation
    /// or during a non-fatal failure branch. Live trust state is
    /// unchanged (or has been rolled back). The inner
    /// [`ReloadApplyError`] preserves the exact Run 070 reason.
    ApplyRejected {
        error: ReloadApplyError,
    },
    /// Run 070 apply pipeline ran into a swap / eviction / commit
    /// failure AFTER a successful state swap, and the rollback
    /// succeeded. Live state is back on the previous snapshot;
    /// sequence file is unchanged; marker file is unchanged. Mirrors
    /// `task/RUN_070_TASK.txt` rollback semantics.
    ApplyRollbackSucceeded {
        error: ReloadApplyError,
    },
    /// FATAL: Run 070 apply pipeline ran into a commit failure AFTER
    /// state swap and session eviction succeeded, AND the rollback
    /// itself failed. Live trust state may now be ahead of the on-disk
    /// sequence record. Operator MUST stop the node and recover
    /// offline.
    ApplyFatalRollbackFailed {
        error: ReloadApplyError,
    },
    /// Run 070 apply pipeline succeeded AND the v2 marker was persisted
    /// after `commit_sequence` per Run 134/138 discipline.
    MarkerPersistedAfterCommit {
        applied: AppliedCandidate,
    },
    /// Run 070 apply pipeline succeeded — the trust-bundle sequence
    /// has advanced — BUT the post-commit v2 marker persist failed.
    /// **Fatal / operator-actionable.** On-disk marker is stale-by-one;
    /// operator MUST be notified and reconcile offline.
    MarkerPersistFailedAfterCommit {
        applied: AppliedCandidate,
        marker_error: String,
    },
}

impl PeerDrivenApplyOutcome {
    /// `true` iff the outcome corresponds to a fully-applied peer-driven
    /// candidate (Run 070 apply succeeded AND marker discipline ok).
    pub fn is_applied(&self) -> bool {
        matches!(
            self,
            Self::ApplySucceeded { .. } | Self::MarkerPersistedAfterCommit { .. }
        )
    }

    /// `true` iff the outcome is one of the safe non-mutating refusal
    /// variants where the Run 070 apply pipeline was never invoked.
    pub fn is_pre_apply_refusal(&self) -> bool {
        matches!(
            self,
            Self::Disabled
                | Self::RefusedMainNet
                | Self::RefusedEnvironmentPolicy
                | Self::CandidateNotFound
                | Self::CandidateExpired { .. }
                | Self::CandidateNotValidated
                | Self::CandidateWrongDomain { .. }
                | Self::CandidateMarkerConflict { .. }
        )
    }

    /// `true` iff the outcome requires fatal/operator-actionable
    /// follow-up per Run 070 / Run 134 / Run 138 discipline.
    pub fn is_fatal_operator_actionable(&self) -> bool {
        matches!(
            self,
            Self::ApplyFatalRollbackFailed { .. } | Self::MarkerPersistFailedAfterCommit { .. }
        )
    }
}

/// Identifier of a staged peer candidate inside a
/// [`PeerCandidateStagingQueue`]. Run 148 keys by the validated
/// candidate's `(fingerprint_prefix, sequence)` pair because that is
/// the unique identifier the staging queue records in
/// [`StagedPeerCandidate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedPeerCandidateId {
    pub fingerprint_prefix: String,
    pub sequence: u64,
}

impl StagedPeerCandidateId {
    pub fn new(fingerprint_prefix: impl Into<String>, sequence: u64) -> Self {
        Self {
            fingerprint_prefix: fingerprint_prefix.into(),
            sequence,
        }
    }

    fn matches(&self, entry: &StagedPeerCandidate) -> bool {
        entry.fingerprint_prefix == self.fingerprint_prefix && entry.sequence == self.sequence
    }
}

/// Locate a staged candidate by id. Sweeps expired entries first (Run
/// 145 lazy TTL contract) so the freshness check below sees a
/// consistent view.
fn find_staged_candidate(
    queue: &mut PeerCandidateStagingQueue,
    id: &StagedPeerCandidateId,
    now_unix_secs: u64,
) -> Option<StagedPeerCandidate> {
    queue.purge_expired(now_unix_secs);
    queue
        .entries()
        .into_iter()
        .find(|entry| id.matches(entry))
}

/// Run 148 peer-driven apply controller entry point. **Narrow,
/// fail-closed, source/test-only.**
///
/// Pipeline (matches Run 148 task §Required pipeline):
///
/// 1. Evaluate the policy (`enabled`, MainNet refusal, environment
///    permission).
/// 2. Locate the staged candidate by id and enforce freshness + domain
///    + validation flags.
/// 3. Run the pre-apply v2 marker decision via
///    [`V2MarkerCoordinator::decide_pre_apply`] when
///    `require_v2_ratification == true`.
/// 4. Invoke the existing Run 070 apply contract
///    ([`apply_validated_candidate_with_previous`]) with the
///    caller-supplied [`PeerDrivenApplyInvocation`].
/// 5. On success, run the post-commit marker persist via
///    [`V2MarkerCoordinator::persist_after_commit`].
/// 6. Map every Run 070 error variant + every marker outcome to a
///    typed [`PeerDrivenApplyOutcome`].
///
/// # Invariants
///
/// - On every non-applied outcome the controller does NOT directly
///   write the sequence file, the marker file, or live trust state.
///   The only mutations come from the existing Run 070 pipeline and
///   the existing v2 marker persist boundary helper.
/// - MainNet is refused **before** the staged-candidate lookup, the
///   pre-apply marker check, and any Run 070 apply invocation.
/// - The post-commit marker persist is invoked at most once and only
///   after `commit_sequence` succeeded.
pub fn try_apply_staged_peer_candidate(
    staged_candidate_id: &StagedPeerCandidateId,
    staging_queue: &mut PeerCandidateStagingQueue,
    invocation: PeerDrivenApplyInvocation<'_>,
    marker_coordinator: &mut dyn V2MarkerCoordinator,
    policy: &PeerDrivenApplyPolicy,
    runtime_domain: &PeerDrivenApplyRuntimeDomain,
    now_unix_secs: u64,
) -> PeerDrivenApplyOutcome {
    // 1. Policy gating. Disabled and MainNet refusal short-circuit
    //    BEFORE the staging-queue is even consulted; this guarantees
    //    the negative R-tests can assert "queue untouched" without
    //    relying on internal ordering.
    if !policy.enabled {
        return PeerDrivenApplyOutcome::Disabled;
    }
    // MainNet refusal is unconditional regardless of `allow_mainnet`.
    if matches!(policy.environment, NetworkEnvironment::Mainnet)
        || matches!(runtime_domain.environment, NetworkEnvironment::Mainnet)
    {
        return PeerDrivenApplyOutcome::RefusedMainNet;
    }
    if policy.environment != runtime_domain.environment {
        // Policy and runtime disagree on environment; fail closed.
        return PeerDrivenApplyOutcome::RefusedEnvironmentPolicy;
    }
    match runtime_domain.environment {
        NetworkEnvironment::Devnet if !policy.allow_devnet => {
            return PeerDrivenApplyOutcome::RefusedEnvironmentPolicy;
        }
        NetworkEnvironment::Testnet if !policy.allow_testnet => {
            return PeerDrivenApplyOutcome::RefusedEnvironmentPolicy;
        }
        NetworkEnvironment::Mainnet => {
            // Unreachable thanks to the explicit MainNet refusal above,
            // but kept as a defence-in-depth fallthrough.
            return PeerDrivenApplyOutcome::RefusedMainNet;
        }
        _ => {}
    }

    // 2. Locate staged candidate (Run 148 §Required pipeline step 3/5).
    let staged = match find_staged_candidate(staging_queue, staged_candidate_id, now_unix_secs) {
        Some(s) => s,
        None => {
            if policy.require_staged_candidate {
                return PeerDrivenApplyOutcome::CandidateNotFound;
            }
            // No staged candidate but caller said it is optional; fail
            // closed anyway in Run 148 — the spec only allows applying
            // staged candidates.
            return PeerDrivenApplyOutcome::CandidateNotFound;
        }
    };

    // 2a. Freshness — TTL enforced at apply time, not only at staging
    // time (Run 148 §6 Candidate freshness).
    let age_secs = now_unix_secs.saturating_sub(staged.staged_at_unix_secs);
    if age_secs > policy.max_candidate_age_secs {
        return PeerDrivenApplyOutcome::CandidateExpired {
            staged_at_unix_secs: staged.staged_at_unix_secs,
            age_secs,
            max_age_secs: policy.max_candidate_age_secs,
        };
    }
    // 2b. Signature-verified flag must be true. The staging queue
    // records what the upstream Run 142 validator reported; a `false`
    // here would mean the candidate slipped past the Run 142 gate,
    // which is impossible under Run 142 invariants but checked
    // defensively.
    if !staged.signature_verified {
        return PeerDrivenApplyOutcome::CandidateNotValidated;
    }
    // 2c. Wrong-domain refusal — the staged candidate must declare the
    // same environment + chain id as the receiving node.
    if staged.environment != runtime_domain.trust_env()
        || staged.chain_id_hex != runtime_domain.chain_id_hex
    {
        return PeerDrivenApplyOutcome::CandidateWrongDomain {
            candidate_environment: staged.environment,
            candidate_chain_id_hex: staged.chain_id_hex.clone(),
            runtime_environment: runtime_domain.environment,
            runtime_chain_id_hex: runtime_domain.chain_id_hex.clone(),
        };
    }

    // 3. Pre-apply v2 marker decision (Run 134/138 discipline). This
    // step runs BEFORE any Run 070 invocation so a marker refusal
    // never burns any sequence / never causes a swap / never writes
    // the marker file.
    if policy.require_v2_ratification {
        if let Err(reason) = marker_coordinator.decide_pre_apply() {
            return PeerDrivenApplyOutcome::CandidateMarkerConflict { reason };
        }
    }

    // 4. Reuse Run 070 apply contract. The controller intentionally
    // does NOT introduce a new apply algorithm; the
    // `apply_validated_candidate_with_previous` entry point drives
    // `validate → snapshot previous → swap → evict_sessions →
    // commit_sequence` and the rollback / fatal semantics.
    let PeerDrivenApplyInvocation {
        inputs,
        live_apply_ctx,
        previous_fingerprint_prefix,
        previous_sequence,
    } = invocation;
    let apply_result = apply_validated_candidate_with_previous(
        inputs,
        ApplyMode::ApplyLive,
        Some(live_apply_ctx),
        previous_fingerprint_prefix,
        previous_sequence,
    );

    // 5. Map Run 070 result + post-commit marker discipline to a typed
    // outcome.
    match apply_result {
        Ok(applied) => {
            // Apply succeeded. If v2 marker discipline is required,
            // the post-commit persist runs now and ONLY now. A failure
            // here is fatal/operator-actionable.
            if policy.require_v2_ratification {
                if let Err(marker_error) = marker_coordinator.persist_after_commit() {
                    return PeerDrivenApplyOutcome::MarkerPersistFailedAfterCommit {
                        applied,
                        marker_error,
                    };
                }
                PeerDrivenApplyOutcome::MarkerPersistedAfterCommit { applied }
            } else {
                PeerDrivenApplyOutcome::ApplySucceeded { applied }
            }
        }
        // Validation failure or no-op error before swap — no rollback
        // was needed.
        Err(e @ ReloadApplyError::ValidationFailed(_))
        | Err(e @ ReloadApplyError::UnsupportedRuntimeContext(_))
        | Err(e @ ReloadApplyError::LiveReloadDisabled(_))
        | Err(e @ ReloadApplyError::StateSwapFailed(_)) => {
            PeerDrivenApplyOutcome::ApplyRejected { error: e }
        }
        Err(
            e @ ReloadApplyError::SessionEvictionFailed {
                rollback_ok: true, ..
            },
        )
        | Err(e @ ReloadApplyError::SequenceCommitFailed(_)) => {
            PeerDrivenApplyOutcome::ApplyRollbackSucceeded { error: e }
        }
        Err(
            e @ ReloadApplyError::SessionEvictionFailed {
                rollback_ok: false, ..
            },
        )
        | Err(e @ ReloadApplyError::SequenceCommitFailedRollbackAlsoFailed { .. }) => {
            PeerDrivenApplyOutcome::ApplyFatalRollbackFailed { error: e }
        }
    }
}

/// Helper: human-readable age duration of a staged candidate for
/// operator logs. Not used by the policy decision (the policy uses
/// raw seconds) but useful for callers that surface refusals.
pub fn staged_candidate_age(
    staged_at_unix_secs: u64,
    now_unix_secs: u64,
) -> Duration {
    Duration::from_secs(now_unix_secs.saturating_sub(staged_at_unix_secs))
}

#[cfg(test)]
mod tests {
    //! In-module unit tests cover the policy / outcome / id types.
    //! End-to-end controller behaviour (driving Run 070 through a
    //! `FakeLiveTrustApplyContext` + the staging queue) lives in
    //! `tests/run_148_peer_driven_apply_devnet_tests.rs`.
    use super::*;

    #[test]
    fn default_policy_is_disabled_on_every_environment() {
        let p = PeerDrivenApplyPolicy::default();
        assert!(!p.enabled);
        assert!(!p.allow_devnet);
        assert!(!p.allow_testnet);
        assert!(!p.allow_mainnet);
        assert!(p.require_staged_candidate);
        assert!(p.require_v2_ratification);
        assert_eq!(p.max_candidate_age_secs, DEFAULT_MAX_CANDIDATE_AGE_SECS);
        assert_eq!(p.environment, NetworkEnvironment::Devnet);
    }

    #[test]
    fn devnet_enabled_policy_has_devnet_only_permissions() {
        let p = PeerDrivenApplyPolicy::devnet_enabled();
        assert!(p.enabled);
        assert!(p.allow_devnet);
        assert!(!p.allow_testnet);
        assert!(!p.allow_mainnet);
        assert!(p.require_staged_candidate);
        assert!(p.require_v2_ratification);
        assert_eq!(p.environment, NetworkEnvironment::Devnet);
    }

    #[test]
    fn testnet_enabled_policy_has_testnet_only_permissions() {
        let p = PeerDrivenApplyPolicy::testnet_enabled();
        assert!(p.enabled);
        assert!(!p.allow_devnet);
        assert!(p.allow_testnet);
        assert!(!p.allow_mainnet);
        assert_eq!(p.environment, NetworkEnvironment::Testnet);
    }

    #[test]
    fn mainnet_attempted_policy_keeps_allow_mainnet_flag_set() {
        // Sanity: the convenience constructor leaves `allow_mainnet =
        // true` so callers can prove the controller still refuses.
        let p = PeerDrivenApplyPolicy::mainnet_attempted();
        assert!(p.enabled);
        assert!(p.allow_mainnet);
        assert_eq!(p.environment, NetworkEnvironment::Mainnet);
    }

    #[test]
    fn outcome_classification_helpers() {
        let disabled = PeerDrivenApplyOutcome::Disabled;
        assert!(disabled.is_pre_apply_refusal());
        assert!(!disabled.is_applied());
        assert!(!disabled.is_fatal_operator_actionable());

        let mainnet = PeerDrivenApplyOutcome::RefusedMainNet;
        assert!(mainnet.is_pre_apply_refusal());

        let conflict = PeerDrivenApplyOutcome::CandidateMarkerConflict {
            reason: "test".into(),
        };
        assert!(conflict.is_pre_apply_refusal());
        assert!(!conflict.is_applied());
    }

    #[test]
    fn staged_candidate_id_matching() {
        let id = StagedPeerCandidateId::new("aabbccdd", 7);
        let entry = StagedPeerCandidate {
            peer_id: Some("p".into()),
            fingerprint_prefix: "aabbccdd".into(),
            fingerprint_hex: "aabbccdd".repeat(8),
            sequence: 7,
            environment: TrustBundleEnvironment::Devnet,
            chain_id_hex: format!("{:016x}", 1_u64),
            staged_at_unix_secs: 100,
            authority_marker_digest: None,
            signature_verified: true,
        };
        assert!(id.matches(&entry));

        let wrong_seq = StagedPeerCandidateId::new("aabbccdd", 8);
        assert!(!wrong_seq.matches(&entry));

        let wrong_fp = StagedPeerCandidateId::new("11223344", 7);
        assert!(!wrong_fp.matches(&entry));
    }

    #[test]
    fn no_v2_marker_coordinator_is_noop() {
        let mut c = NoV2MarkerCoordinator;
        assert!(c.decide_pre_apply().is_ok());
        assert!(c.persist_after_commit().is_ok());
    }

    #[test]
    fn staged_candidate_age_helper_is_saturating() {
        // Sane forward case.
        let d = staged_candidate_age(100, 250);
        assert_eq!(d.as_secs(), 150);
        // Clock skew backwards must not panic / underflow.
        let d2 = staged_candidate_age(500, 100);
        assert_eq!(d2.as_secs(), 0);
    }
}