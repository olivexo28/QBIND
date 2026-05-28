//! Run 145 (C4 piece: peer-driven trust-bundle apply, staged candidate queue —
//! source/test scaffold, disabled-by-default, **non-applying**): a safe,
//! library-level staging layer that can receive **already-validated** peer
//! trust-bundle candidates from the Run 142/143 live inbound `0x05`
//! validation-only path and record them as locally **staged** candidates
//! for future operator/governance decision.
//!
//! # Strict scope (matches `task/RUN_145_TASK.txt`)
//!
//! - Source/test scaffold **only**. No release-binary evidence is claimed
//!   in this run; release-binary staging evidence is deferred to Run 146.
//! - **No live apply** is performed. The module exposes **no** `apply` /
//!   `apply_validated_candidate` / `apply_validated_candidate_with_previous`
//!   entry point. A staged candidate is **not** trusted, **not** applied,
//!   **not** persisted as accepted authority.
//! - **No mutation** of [`crate::pqc_live_trust::LivePqcTrustState`].
//! - **No write** to `pqc_trust_bundle_sequence.json`.
//! - **No write** to `pqc_authority_state.json` (no authority-marker
//!   write).
//! - **No P2P / KEMTLS session eviction.**
//! - **No call** into Run 070
//!   [`crate::pqc_live_trust_apply::apply_validated_candidate`] or
//!   [`crate::pqc_live_trust_apply::apply_validated_candidate_with_previous`].
//! - **No SIGHUP / reload-apply invocation.**
//! - **No new wire format.** The live inbound `0x05` envelope and
//!   `LivePeerCandidateWireDispatcher` route remain unchanged.
//! - **No trust-bundle / ratification-sidecar / authority-marker / wire
//!   schema change.**
//! - **No MainNet enablement.** MainNet peer-driven staging is refused
//!   for now, even with `enabled = true`, until a future governance /
//!   ratification / KMS-HSM proof type exists. **Local peer majority is
//!   not authority.**
//! - **No KMS / HSM.**
//! - **No governance implementation.**
//! - **No signing-key rotation / revocation lifecycle.**
//! - **Does not weaken** existing validation-only or propagation-only
//!   behaviour. Runs 132/133/142/143 invariants remain intact: the
//!   staging layer is *downstream* of validation and is end-of-line for
//!   the data it receives.
//! - **Does not claim** full C4 or C5 closure.
//!
//! # Component identity
//!
//! The staging surface is the [`PeerCandidateStagingQueue`] — a bounded,
//! deduplicated, TTL-bounded, **disabled-by-default**, environment-gated,
//! per-peer-bounded, in-memory queue of [`StagedPeerCandidate`] entries.
//!
//! - Disabled-by-default: [`PeerDrivenStagingPolicy::default`] returns
//!   `enabled = false` and `allow_devnet = allow_testnet = allow_mainnet
//!   = false`.
//! - Environment-gated:
//!   - **DevNet**: stages **only** when `enabled && allow_devnet`.
//!   - **TestNet**: stages **only** when `enabled && allow_testnet`.
//!     The caller (production-binary integration in a future Run 146/147)
//!     MUST additionally have run v2 ratification validation through the
//!     Run 130 verifier and the Run 132/142 marker validation-only check
//!     **before** invoking the staging queue, because the staging queue
//!     consumes a [`ValidatedPeerCandidate`] — the type produced by the
//!     existing validation-only path.
//!   - **MainNet**: **refused** unconditionally for now, regardless of
//!     `enabled`/`allow_mainnet`. The refusal is fail-closed and
//!     intentional; MainNet peer-driven trust-bundle apply requires a
//!     governance / ratification / KMS-HSM authority that does not yet
//!     exist.
//! - Bounded:
//!   - `max_staged_candidates` — global cap; **eviction policy is
//!     reject-new** (safer than silent eviction).
//!   - `max_candidates_per_peer` — per-peer cap; reject-new.
//!   - `ttl_secs` — entries older than `ttl_secs` are purged by the
//!     `purge_expired` sweep that runs lazily on every read/insert.
//!   - Duplicate suppression — by `(fingerprint_prefix, sequence,
//!     authority_marker_digest)` triple. A byte-identical resubmission
//!     of an already-staged candidate returns
//!     [`StagingOutcome::AlreadyStaged`].
//!
//! # Integration point
//!
//! Run 145 is intentionally **library-level only**. The live inbound
//! `0x05` validation-only path
//! ([`crate::pqc_peer_candidate_wire::LivePeerCandidateWireDispatcher`])
//! is **not** wired to call [`PeerCandidateStagingQueue::try_stage_validated`]
//! in this run, because doing so would require runtime flag plumbing
//! (`--p2p-peer-driven-staging-*` family) which the Run 145 task scope
//! explicitly excludes ("Do not add a CLI flag unless absolutely
//! necessary"). The future production-binary hook for Run 146 is:
//!
//! 1. Operator (DevNet only; or TestNet only with an explicit
//!    `--p2p-peer-driven-staging-testnet-enable` flag and a verified v2
//!    ratification) enables peer-driven staging via a hidden CLI flag.
//!    MainNet refuses to bind.
//! 2. `qbind-node` `main.rs` constructs a [`PeerDrivenStagingPolicy`]
//!    from the parsed flag and the resolved
//!    [`qbind_types::NetworkEnvironment`].
//! 3. `LivePeerCandidateWireDispatcher` is given a shared
//!    `Arc<Mutex<PeerCandidateStagingQueue>>` and, on every
//!    `PeerCandidateWireOutcome::ValidatorRan(PeerCandidateOutcome::
//!    Validated(v))`, invokes
//!    `queue.try_stage_validated(&v, marker_digest, now_unix_secs)`.
//! 4. The dispatcher continues to **NOT** call Run 070 apply, **NOT**
//!    swap `LivePqcTrustState`, **NOT** write
//!    `pqc_trust_bundle_sequence.json`, **NOT** write
//!    `pqc_authority_state.json`, and **NOT** evict sessions. Staging
//!    is a parallel, observation-only audit trail.
//!
//! Run 145 itself adds **no** CLI flag, **no** dispatcher field, and
//! **no** production caller. The module is exercised by the Run 145 test
//! suite (`tests/run_145_peer_candidate_staging_tests.rs`) and is dead
//! code in the release binary until Run 146.
//!
//! # See also
//!
//! - `task/RUN_145_TASK.txt` — task statement.
//! - `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_145.md` — Run 145 design /
//!   evidence report.
//! - `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md` —
//!   Run 144 safety specification (Phase 2 staging requirements).
//! - `docs/whitepaper/contradiction.md` — Run 145 paragraph.

use std::collections::VecDeque;

use qbind_types::NetworkEnvironment;

use crate::pqc_peer_candidate_wire::PeerCandidateWireOutcome;
use crate::pqc_trust_bundle::TrustBundleEnvironment;
use crate::pqc_trust_peer_candidate::{PeerCandidateOutcome, ValidatedPeerCandidate};

/// Default global cap on the number of staged peer-candidate entries.
///
/// Picked small enough that a single malicious peer cannot blow up node
/// memory, while leaving enough headroom for several legitimate
/// candidates from distinct peers during a normal trust-bundle rotation
/// window. Eviction policy when at cap is **reject-new** (see
/// [`PeerCandidateStagingQueue::try_stage_validated`]).
pub const DEFAULT_MAX_STAGED_CANDIDATES: usize = 16;

/// Default per-peer cap on staged candidates. Prevents a single peer
/// from filling the global queue alone.
pub const DEFAULT_MAX_CANDIDATES_PER_PEER: usize = 4;

/// Default time-to-live for a staged candidate, in seconds. Older
/// entries are purged on the next `purge_expired` sweep (which is
/// invoked lazily by `try_stage_validated` and `entries`). Picked to be
/// long enough for an operator to act on a candidate during a normal
/// rotation, but short enough that stale candidates cannot accumulate
/// indefinitely if nobody acts.
pub const DEFAULT_TTL_SECS: u64 = 300;

/// Policy describing whether — and on which environment — the
/// [`PeerCandidateStagingQueue`] is allowed to accept staged peer-driven
/// trust-bundle candidates.
///
/// **Disabled by default on every environment.** MainNet remains
/// refused even with `enabled = true`, until a future
/// governance / ratification / KMS-HSM proof type exists.
#[derive(Debug, Clone)]
pub struct PeerDrivenStagingPolicy {
    /// Master enable switch. If `false`, every call to
    /// [`PeerCandidateStagingQueue::try_stage_validated`] returns
    /// [`StagingOutcome::RefusedDisabled`].
    pub enabled: bool,
    /// Resolved runtime environment of the receiving node.
    pub environment: NetworkEnvironment,
    /// Permit staging on DevNet when `enabled == true`.
    pub allow_devnet: bool,
    /// Permit staging on TestNet when `enabled == true` AND the caller
    /// has independently run v2 ratification validation through the
    /// existing Run 130 verifier and the Run 132/142 marker
    /// validation-only check before invoking the queue.
    pub allow_testnet: bool,
    /// Permit staging on MainNet. **IGNORED for now** — Run 145
    /// MainNet staging is refused unconditionally. Kept on the policy
    /// struct so a future governance / KMS-HSM gate run can flip it
    /// behind a separate authority check without API churn.
    pub allow_mainnet: bool,
    /// Maximum number of staged candidates retained globally. Eviction
    /// policy when at capacity is **reject-new**.
    pub max_staged_candidates: usize,
    /// Maximum number of staged candidates retained for any one peer
    /// (identified by `peer_id`). Reject-new when at capacity.
    pub max_candidates_per_peer: usize,
    /// TTL for a staged entry, in seconds.
    pub ttl_secs: u64,
}

impl Default for PeerDrivenStagingPolicy {
    /// **Disabled-by-default on every environment.**
    fn default() -> Self {
        Self {
            enabled: false,
            environment: NetworkEnvironment::Devnet,
            allow_devnet: false,
            allow_testnet: false,
            allow_mainnet: false,
            max_staged_candidates: DEFAULT_MAX_STAGED_CANDIDATES,
            max_candidates_per_peer: DEFAULT_MAX_CANDIDATES_PER_PEER,
            ttl_secs: DEFAULT_TTL_SECS,
        }
    }
}

impl PeerDrivenStagingPolicy {
    /// Convenience constructor for a DevNet-only enabled policy with
    /// default bounds. Still returns a policy that **refuses TestNet
    /// and MainNet** even at runtime.
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

    /// Convenience constructor for a TestNet-only enabled policy with
    /// default bounds. Callers are responsible for ensuring the
    /// upstream v2 ratification verifier already accepted the candidate
    /// before invoking the queue.
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
    /// and `allow_mainnet = true`, but the queue **still refuses**
    /// staging in Run 145 because no governance authority exists.
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

    /// Decide whether the (environment, flag) tuple permits staging.
    /// Pure helper; never mutates state.
    fn permitted(&self) -> Option<StagingRefusal> {
        if !self.enabled {
            return Some(StagingRefusal::Disabled);
        }
        match self.environment {
            NetworkEnvironment::Devnet => {
                if self.allow_devnet {
                    None
                } else {
                    Some(StagingRefusal::EnvironmentPolicy)
                }
            }
            NetworkEnvironment::Testnet => {
                if self.allow_testnet {
                    None
                } else {
                    Some(StagingRefusal::EnvironmentPolicy)
                }
            }
            NetworkEnvironment::Mainnet => {
                // MainNet is refused unconditionally for now —
                // `allow_mainnet` is intentionally ignored. Local
                // peer majority is NOT authority on MainNet.
                Some(StagingRefusal::MainnetGovernanceMissing)
            }
        }
    }
}

/// Reason a [`PeerCandidateStagingQueue::try_stage_validated`] call did
/// not produce a [`StagingOutcome::Staged`] result. Used internally by
/// the queue to keep refusal reasons exhaustively typed.
#[derive(Debug, Clone, PartialEq, Eq)]
enum StagingRefusal {
    Disabled,
    EnvironmentPolicy,
    MainnetGovernanceMissing,
}

/// Single staged peer-driven trust-bundle candidate metadata record.
///
/// **Non-authoritative.** Holding a [`StagedPeerCandidate`] does NOT
/// mean the candidate has been applied, propagated, or persisted as
/// accepted authority. It is a memory-only observation for future
/// operator / governance decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedPeerCandidate {
    /// Originating peer id (log-safe; may be `None` if upstream did
    /// not supply one).
    pub peer_id: Option<String>,
    /// 8-char lowercase hex fingerprint prefix of the validated
    /// candidate bundle's canonical encoding.
    pub fingerprint_prefix: String,
    /// Full 64-char lowercase hex SHA3-256 fingerprint of the validated
    /// candidate bundle's canonical encoding.
    pub fingerprint_hex: String,
    /// Bundle-declared sequence number (validated by the Run 069
    /// loader; **not persisted** by the staging queue).
    pub sequence: u64,
    /// Canonical environment of the validated candidate bundle.
    pub environment: TrustBundleEnvironment,
    /// 16-char lowercase hex chain id of the validated candidate.
    pub chain_id_hex: String,
    /// Wall-clock seconds at which the candidate was staged (used by
    /// the TTL sweep).
    pub staged_at_unix_secs: u64,
    /// Authority-marker digest binding the candidate to the receiver's
    /// expected authority. Optional because v1-only markers may not
    /// expose a digest; when present, contributes to the dedup key.
    pub authority_marker_digest: Option<String>,
    /// Whether the v2 ratification sidecar was verified for this
    /// candidate. The staging queue does NOT verify ratification
    /// itself; it records what the upstream
    /// [`ValidatedPeerCandidate`] reported.
    pub signature_verified: bool,
}

/// Outcome of a single [`PeerCandidateStagingQueue::try_stage_validated`]
/// or [`PeerCandidateStagingQueue::try_stage_outcome`] call.
///
/// **Every variant is non-mutating for live trust state / sequence
/// persistence / P2P sessions / authority marker.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StagingOutcome {
    /// The candidate metadata was recorded in the staging queue.
    /// **NOT applied. NOT propagated. NOT persisted as authority.**
    Staged {
        fingerprint_prefix: String,
        sequence: u64,
    },
    /// A byte-identical staged candidate already exists in the queue.
    /// Returned as the deduplication signal; queue did not grow.
    AlreadyStaged {
        fingerprint_prefix: String,
        sequence: u64,
    },
    /// `PeerDrivenStagingPolicy::enabled == false`. Default outcome.
    RefusedDisabled,
    /// Environment policy refused the candidate. Two flavours:
    /// the environment's `allow_*` switch is `false`, or the
    /// environment is MainNet (refused unconditionally in Run 145).
    RefusedEnvironmentPolicy,
    /// Caller provided a [`PeerCandidateWireOutcome`] that did NOT
    /// resolve to `Validated`. The staging queue only accepts
    /// already-validated candidates; invalid / rejected /
    /// rate-limited / oversize / duplicate-suppressed / disabled
    /// outcomes never enter staging.
    RefusedNotValidated,
    /// The global staging cap has been reached. Eviction policy is
    /// **reject-new** in Run 145.
    RefusedGlobalCapacity {
        cap: usize,
    },
    /// The per-peer staging cap has been reached for the originating
    /// peer. Eviction policy is **reject-new**.
    RefusedPerPeerCapacity {
        cap: usize,
    },
}

impl StagingOutcome {
    /// `true` iff the outcome corresponds to a newly-recorded staged
    /// entry (not a dedup hit, not a refusal).
    pub fn is_staged(&self) -> bool {
        matches!(self, Self::Staged { .. })
    }

    /// `true` iff the outcome is `AlreadyStaged` (dedup hit).
    pub fn is_already_staged(&self) -> bool {
        matches!(self, Self::AlreadyStaged { .. })
    }

    /// `true` iff the outcome is any refusal variant.
    pub fn is_refused(&self) -> bool {
        matches!(
            self,
            Self::RefusedDisabled
                | Self::RefusedEnvironmentPolicy
                | Self::RefusedNotValidated
                | Self::RefusedGlobalCapacity { .. }
                | Self::RefusedPerPeerCapacity { .. }
        )
    }
}

/// Bounded, deduplicated, TTL-bounded, disabled-by-default,
/// environment-gated, per-peer-bounded, in-memory queue of staged
/// peer-driven trust-bundle candidates.
///
/// The queue is **non-applying**:
///
/// - **No call** to Run 070
///   [`crate::pqc_live_trust_apply::apply_validated_candidate`] or
///   [`crate::pqc_live_trust_apply::apply_validated_candidate_with_previous`].
/// - **No mutation** of `LivePqcTrustState`.
/// - **No write** to `pqc_trust_bundle_sequence.json`.
/// - **No write** to `pqc_authority_state.json`.
/// - **No session eviction.**
/// - **No SIGHUP / reload-apply / process-start apply invocation.**
/// - **No propagation.** Staging does not imply propagation; propagation
///   remains governed by the existing Run 088 / Run 143 rules.
#[derive(Debug)]
pub struct PeerCandidateStagingQueue {
    policy: PeerDrivenStagingPolicy,
    entries: VecDeque<StagedPeerCandidate>,
}

impl PeerCandidateStagingQueue {
    /// Construct a new queue under `policy`. The queue starts empty.
    pub fn new(policy: PeerDrivenStagingPolicy) -> Self {
        Self {
            policy,
            entries: VecDeque::new(),
        }
    }

    /// Read-only view of the active policy.
    pub fn policy(&self) -> &PeerDrivenStagingPolicy {
        &self.policy
    }

    /// Number of currently-staged entries (excluding expired entries
    /// that have not yet been swept; call [`purge_expired`] first for
    /// strict liveness).
    ///
    /// [`purge_expired`]: Self::purge_expired
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` iff [`len`](Self::len) returns 0.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Snapshot of the currently-staged entries. Does **not** mutate
    /// any state and does **not** sweep TTL — callers wanting a strict
    /// liveness view should call [`purge_expired`] first.
    ///
    /// [`purge_expired`]: Self::purge_expired
    pub fn entries(&self) -> Vec<StagedPeerCandidate> {
        self.entries.iter().cloned().collect()
    }

    /// Sweep entries whose age exceeds `policy.ttl_secs` relative to
    /// `now_unix_secs`. Returns the number of entries removed.
    /// This is the **only** lifecycle removal path in Run 145 — staged
    /// candidates are never "applied" by the queue itself.
    pub fn purge_expired(&mut self, now_unix_secs: u64) -> usize {
        let ttl = self.policy.ttl_secs;
        let before = self.entries.len();
        self.entries.retain(|entry| {
            let age = now_unix_secs.saturating_sub(entry.staged_at_unix_secs);
            age <= ttl
        });
        before - self.entries.len()
    }

    /// True iff the queue already contains an entry matching the
    /// dedup key `(fingerprint_prefix, sequence, authority_marker_digest)`.
    fn contains_dedup(
        &self,
        fingerprint_prefix: &str,
        sequence: u64,
        authority_marker_digest: Option<&str>,
    ) -> bool {
        self.entries.iter().any(|e| {
            e.fingerprint_prefix == fingerprint_prefix
                && e.sequence == sequence
                && e.authority_marker_digest.as_deref() == authority_marker_digest
        })
    }

    /// Number of currently-staged entries originating from a given peer
    /// id (`None` peer ids are bucketed separately).
    fn count_for_peer(&self, peer_id: Option<&str>) -> usize {
        self.entries
            .iter()
            .filter(|e| e.peer_id.as_deref() == peer_id)
            .count()
    }

    /// Attempt to stage a **validation-accepted** peer candidate.
    ///
    /// The caller is responsible for having already run the Run 142/143
    /// validation-only path (Run 069 loader, Run 130 v2 verifier, Run
    /// 132/142 v2 marker validation-only check, Run 088 dedup /
    /// rate-limit / envelope checks). The staging queue **does NOT**
    /// re-validate the candidate; it only records non-authoritative
    /// metadata for later operator/governance decision.
    ///
    /// Returns [`StagingOutcome::Staged`] on first successful insert,
    /// [`StagingOutcome::AlreadyStaged`] on a dedup hit, or one of the
    /// `Refused*` variants on a policy / capacity violation.
    ///
    /// **Invariant**: under **every** return path, this method does
    /// **NOT**:
    ///
    /// - mutate [`crate::pqc_live_trust::LivePqcTrustState`];
    /// - write `pqc_trust_bundle_sequence.json`;
    /// - write `pqc_authority_state.json`;
    /// - call Run 070 apply;
    /// - call SIGHUP / reload-apply / process-start apply;
    /// - evict P2P / KEMTLS sessions;
    /// - propagate or rebroadcast the candidate.
    pub fn try_stage_validated(
        &mut self,
        validated: &ValidatedPeerCandidate,
        authority_marker_digest: Option<String>,
        now_unix_secs: u64,
    ) -> StagingOutcome {
        // Lazy TTL sweep ensures bounded liveness without spawning a
        // background timer / task.
        self.purge_expired(now_unix_secs);

        match self.policy.permitted() {
            Some(StagingRefusal::Disabled) => return StagingOutcome::RefusedDisabled,
            Some(StagingRefusal::EnvironmentPolicy)
            | Some(StagingRefusal::MainnetGovernanceMissing) => {
                return StagingOutcome::RefusedEnvironmentPolicy
            }
            None => {}
        }

        let fingerprint_prefix = validated.validated.fingerprint_prefix.clone();
        let sequence = validated.validated.sequence;

        if self.contains_dedup(
            &fingerprint_prefix,
            sequence,
            authority_marker_digest.as_deref(),
        ) {
            return StagingOutcome::AlreadyStaged {
                fingerprint_prefix,
                sequence,
            };
        }

        if self.entries.len() >= self.policy.max_staged_candidates {
            return StagingOutcome::RefusedGlobalCapacity {
                cap: self.policy.max_staged_candidates,
            };
        }

        if self.count_for_peer(validated.peer_id.as_deref())
            >= self.policy.max_candidates_per_peer
        {
            return StagingOutcome::RefusedPerPeerCapacity {
                cap: self.policy.max_candidates_per_peer,
            };
        }

        self.entries.push_back(StagedPeerCandidate {
            peer_id: validated.peer_id.clone(),
            fingerprint_prefix: fingerprint_prefix.clone(),
            fingerprint_hex: validated.validated.fingerprint_hex.clone(),
            sequence,
            environment: validated.validated.environment,
            chain_id_hex: validated.validated.chain_id_hex.clone(),
            staged_at_unix_secs: now_unix_secs,
            authority_marker_digest,
            signature_verified: validated.validated.signature_verified,
        });

        StagingOutcome::Staged {
            fingerprint_prefix,
            sequence,
        }
    }

    /// Convenience wrapper around [`try_stage_validated`] that accepts
    /// a raw [`PeerCandidateWireOutcome`] as produced by
    /// [`crate::pqc_peer_candidate_wire::LivePeerCandidateWireDispatcher`].
    /// Refuses anything except
    /// `ValidatorRan(PeerCandidateOutcome::Validated(_))` with
    /// [`StagingOutcome::RefusedNotValidated`] — invalid /
    /// lower-sequence / same-sequence-different-digest / wrong-domain /
    /// ambiguous-v1+v2 candidates are rejected by the upstream
    /// validation gate and never reach a `Validated` variant, so they
    /// can never enter the staging queue.
    ///
    /// [`try_stage_validated`]: Self::try_stage_validated
    pub fn try_stage_outcome(
        &mut self,
        outcome: &PeerCandidateWireOutcome,
        authority_marker_digest: Option<String>,
        now_unix_secs: u64,
    ) -> StagingOutcome {
        match outcome {
            PeerCandidateWireOutcome::ValidatorRan(PeerCandidateOutcome::Validated(v)) => {
                self.try_stage_validated(v, authority_marker_digest, now_unix_secs)
            }
            _ => StagingOutcome::RefusedNotValidated,
        }
    }
}

#[cfg(test)]
mod tests {
    //! In-module unit tests cover policy semantics and queue behaviour
    //! at the type level. End-to-end integration coverage that drives
    //! the queue with real [`ValidatedPeerCandidate`] values built by
    //! the Run 142 live inbound `0x05` dispatcher lives in
    //! `tests/run_145_peer_candidate_staging_tests.rs`.
    use super::*;

    #[test]
    fn default_policy_is_disabled_on_every_environment() {
        let p = PeerDrivenStagingPolicy::default();
        assert!(!p.enabled);
        assert!(!p.allow_devnet);
        assert!(!p.allow_testnet);
        assert!(!p.allow_mainnet);
        assert_eq!(p.environment, NetworkEnvironment::Devnet);
        assert_eq!(p.max_staged_candidates, DEFAULT_MAX_STAGED_CANDIDATES);
        assert_eq!(p.max_candidates_per_peer, DEFAULT_MAX_CANDIDATES_PER_PEER);
        assert_eq!(p.ttl_secs, DEFAULT_TTL_SECS);
    }

    #[test]
    fn mainnet_attempted_policy_is_still_refused_by_permitted() {
        let p = PeerDrivenStagingPolicy::mainnet_attempted();
        assert!(p.enabled);
        assert!(p.allow_mainnet);
        assert!(matches!(
            p.permitted(),
            Some(StagingRefusal::MainnetGovernanceMissing)
        ));
    }

    #[test]
    fn devnet_enabled_policy_permits() {
        let p = PeerDrivenStagingPolicy::devnet_enabled();
        assert!(p.permitted().is_none());
    }

    #[test]
    fn devnet_disabled_policy_refuses_disabled() {
        let mut p = PeerDrivenStagingPolicy::devnet_enabled();
        p.enabled = false;
        assert!(matches!(p.permitted(), Some(StagingRefusal::Disabled)));
    }

    #[test]
    fn testnet_disallowed_refuses_environment_policy() {
        let mut p = PeerDrivenStagingPolicy::testnet_enabled();
        p.allow_testnet = false;
        assert!(matches!(
            p.permitted(),
            Some(StagingRefusal::EnvironmentPolicy)
        ));
    }

    #[test]
    fn empty_queue_invariants() {
        let q = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::default());
        assert_eq!(q.len(), 0);
        assert!(q.is_empty());
        assert!(q.entries().is_empty());
    }

    #[test]
    fn purge_expired_on_empty_queue_is_noop() {
        let mut q = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::default());
        assert_eq!(q.purge_expired(1_000), 0);
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn try_stage_outcome_refuses_non_validated_disabled_branch() {
        // Disabled outcome from a default-constructed validator must
        // never be staged, regardless of policy.
        let mut q = PeerCandidateStagingQueue::new(PeerDrivenStagingPolicy::devnet_enabled());
        let outcome = PeerCandidateWireOutcome::ValidatorRan(PeerCandidateOutcome::Disabled);
        assert_eq!(
            q.try_stage_outcome(&outcome, None, 100),
            StagingOutcome::RefusedNotValidated
        );
        assert!(q.is_empty());
    }
}
