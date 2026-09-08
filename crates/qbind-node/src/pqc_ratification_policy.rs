//! Run 106 — per-environment bundle-signing-key ratification policy.
//!
//! Run 105 introduced the first opt-in enforcement surfaces for
//! [`qbind_ledger::enforce_bundle_signing_key_ratification`]: the
//! startup preflight before sequence-write/root-merge and the
//! `--p2p-trust-bundle-reload-check` non-mutating gate. Both gates
//! were invoked **only** when the operator supplied the hidden
//! `--p2p-trust-bundle-ratification-enforcement-enabled` flag, leaving
//! MainNet unprotected by default.
//!
//! Run 106 closes that gap **for the surfaces Run 105 already wired**
//! by making the gate invocation a per-environment policy decision
//! rather than a flat operator-opt-in:
//!
//! ```text
//! MainNet : ratification enforcement is REQUIRED by default
//!           (the opt-in flag and the legacy-allow flag cannot
//!            disable it; the only effect on MainNet is that the gate
//!            body still runs and refuses anything other than a valid
//!            ratification — defense in depth).
//! TestNet : ratification enforcement is REQUIRED by default; the
//!           legacy allowance is only honoured when the operator
//!           additionally supplies
//!           `--p2p-trust-bundle-allow-unratified-testnet-devnet`.
//! DevNet  : ratification enforcement runs when the operator opts in
//!           via `--p2p-trust-bundle-ratification-enforcement-enabled`,
//!           preserving developer-workflow ergonomics for unsigned
//!           and legacy bundles. DevNet allowances **never** affect
//!           MainNet.
//! ```
//!
//! This module is intentionally tiny and pure:
//!
//! - no I/O, no filesystem, no network, no globals;
//! - no crypto (verification still happens inside
//!   `qbind_ledger::enforce_bundle_signing_key_ratification`);
//! - no new metric family, no new error type;
//! - no change to [`crate::pqc_trust_reload::ReloadCheckInputs`] or
//!   [`crate::pqc_trust_peer_candidate::PeerCandidateRuntimeContext`]
//!   shape (per the Run 105 invariant: those structs have ~18 call
//!   sites across `crates/qbind-node/{src,tests}` and adding fields
//!   to them is the wrong tool — wrapper entry points
//!   `*_with_ratification` already exist and are reused unchanged).
//!
//! Surfaces explicitly **not** covered by Run 106 (see
//! `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_106.md`):
//!
//! - `--p2p-trust-bundle-peer-candidate-check`;
//! - live peer-candidate wire validation
//!   (`crate::pqc_peer_candidate_wire`);
//! - propagation / rebroadcast;
//! - process-start reload-apply (Run 073);
//! - SIGHUP live reload (Run 074).
//!
//! Those surfaces still behave exactly as Run 105 left them and are
//! tracked as deferred residual risk in `docs/whitepaper/contradiction.md`.

use qbind_types::NetworkEnvironment;

/// Per-environment decision about whether the Run 105 ratification
/// gate must be invoked on a given trust-bundle validation surface.
///
/// The variant carries the **reason** for the decision so the
/// operator log can distinguish a MainNet mandatory enforcement from a
/// DevNet operator-opt-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatificationGateDecision {
    /// The gate MUST be invoked. Used on MainNet unconditionally and
    /// on TestNet by default; also used on DevNet when the operator
    /// has explicitly opted in.
    Invoke(GateInvokeReason),
    /// The gate is not invoked on this surface in this environment
    /// configuration. Only ever returned for DevNet when the operator
    /// has not opted in, preserving the pre-Run-106 developer
    /// ergonomics for unsigned and legacy bundles.
    Skip(GateSkipReason),
}

/// Reason the gate was invoked. Carried for operator-log clarity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateInvokeReason {
    /// MainNet default-strict — Run 106. Independent of any flag.
    MainnetDefaultStrict,
    /// TestNet default-strict — Run 106. Independent of the
    /// `--p2p-trust-bundle-ratification-enforcement-enabled` flag.
    TestnetDefaultStrict,
    /// DevNet under explicit operator opt-in via
    /// `--p2p-trust-bundle-ratification-enforcement-enabled`.
    DevnetOperatorOptIn,
}

/// Reason the gate was skipped. Carried for operator-log clarity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateSkipReason {
    /// DevNet without the operator opt-in flag. The gate is not
    /// invoked; this is **not** a passed ratification, it is a
    /// developer-workflow surface left in its pre-Run-105 state.
    DevnetNoOperatorOptIn,
}

impl RatificationGateDecision {
    /// True iff the gate should be invoked.
    pub fn should_invoke(&self) -> bool {
        matches!(self, RatificationGateDecision::Invoke(_))
    }

    /// Short, stable label suitable for operator log lines.
    pub fn label(&self) -> &'static str {
        match self {
            RatificationGateDecision::Invoke(GateInvokeReason::MainnetDefaultStrict) => {
                "mainnet-default-strict"
            }
            RatificationGateDecision::Invoke(GateInvokeReason::TestnetDefaultStrict) => {
                "testnet-default-strict"
            }
            RatificationGateDecision::Invoke(GateInvokeReason::DevnetOperatorOptIn) => {
                "devnet-operator-opt-in"
            }
            RatificationGateDecision::Skip(GateSkipReason::DevnetNoOperatorOptIn) => {
                "devnet-no-operator-opt-in"
            }
        }
    }
}

/// Decide whether the Run 105 ratification gate must be invoked on a
/// trust-bundle validation surface, given the current network
/// environment and the operator-supplied opt-in flag.
///
/// Run 106 contract:
///
/// - MainNet: always `Invoke(MainnetDefaultStrict)`. The operator
///   opt-in flag is ignored — it cannot disable MainNet enforcement,
///   and it does not need to be supplied to enable it.
/// - TestNet: always `Invoke(TestnetDefaultStrict)`. Same reasoning
///   as MainNet; the legacy escape hatch lives inside the gate body
///   (it requires the explicit
///   `--p2p-trust-bundle-allow-unratified-testnet-devnet` flag and
///   the gate refuses it on MainNet via the `policy` field of
///   `RatificationEnforcementInputs`).
/// - DevNet: `Invoke(DevnetOperatorOptIn)` iff the operator supplied
///   `--p2p-trust-bundle-ratification-enforcement-enabled`; otherwise
///   `Skip(DevnetNoOperatorOptIn)`. This preserves the pre-Run-105
///   DevNet ergonomics for unsigned and legacy bundles while keeping
///   the flag-driven Run 105 path available unchanged for DevNet
///   evidence runs.
///
/// This function does NOT perform any crypto verification, does NOT
/// touch the filesystem, and does NOT read any global state. The
/// gate body still runs the full Run 103/105
/// `enforce_bundle_signing_key_ratification` pipeline (signature /
/// chain_id / environment / authority-root binding / canonical
/// genesis hash / candidate key match), and still maps to
/// `RatificationEnforcementPolicy::Strict` on MainNet regardless of
/// any flag.
pub fn ratification_gate_decision(
    env: NetworkEnvironment,
    operator_opt_in: bool,
) -> RatificationGateDecision {
    match env {
        NetworkEnvironment::Mainnet => {
            RatificationGateDecision::Invoke(GateInvokeReason::MainnetDefaultStrict)
        }
        NetworkEnvironment::Testnet => {
            RatificationGateDecision::Invoke(GateInvokeReason::TestnetDefaultStrict)
        }
        NetworkEnvironment::Devnet => {
            if operator_opt_in {
                RatificationGateDecision::Invoke(GateInvokeReason::DevnetOperatorOptIn)
            } else {
                RatificationGateDecision::Skip(GateSkipReason::DevnetNoOperatorOptIn)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_is_strict_by_default_regardless_of_opt_in_flag() {
        // The whole point of Run 106: on MainNet, the operator opt-in
        // flag must NOT be required to invoke the gate, and must NOT
        // be able to disable it.
        let with_flag = ratification_gate_decision(NetworkEnvironment::Mainnet, true);
        let without_flag = ratification_gate_decision(NetworkEnvironment::Mainnet, false);
        assert_eq!(with_flag, without_flag);
        assert!(with_flag.should_invoke());
        assert_eq!(
            with_flag,
            RatificationGateDecision::Invoke(GateInvokeReason::MainnetDefaultStrict)
        );
        assert_eq!(with_flag.label(), "mainnet-default-strict");
    }

    #[test]
    fn testnet_is_strict_by_default_regardless_of_opt_in_flag() {
        let with_flag = ratification_gate_decision(NetworkEnvironment::Testnet, true);
        let without_flag = ratification_gate_decision(NetworkEnvironment::Testnet, false);
        assert_eq!(with_flag, without_flag);
        assert!(with_flag.should_invoke());
        assert_eq!(
            with_flag,
            RatificationGateDecision::Invoke(GateInvokeReason::TestnetDefaultStrict)
        );
        assert_eq!(with_flag.label(), "testnet-default-strict");
    }

    #[test]
    fn devnet_without_opt_in_skips_gate() {
        let d = ratification_gate_decision(NetworkEnvironment::Devnet, false);
        assert!(!d.should_invoke());
        assert_eq!(
            d,
            RatificationGateDecision::Skip(GateSkipReason::DevnetNoOperatorOptIn)
        );
        assert_eq!(d.label(), "devnet-no-operator-opt-in");
    }

    #[test]
    fn devnet_with_opt_in_invokes_gate() {
        let d = ratification_gate_decision(NetworkEnvironment::Devnet, true);
        assert!(d.should_invoke());
        assert_eq!(
            d,
            RatificationGateDecision::Invoke(GateInvokeReason::DevnetOperatorOptIn)
        );
        assert_eq!(d.label(), "devnet-operator-opt-in");
    }

    #[test]
    fn devnet_opt_in_does_not_weaken_mainnet() {
        // Cross-environment regression guard: a DevNet skip decision
        // must never be returned for MainNet, regardless of the flag
        // state, and the MainNet decision must always be Invoke.
        for opt_in in [false, true] {
            let m = ratification_gate_decision(NetworkEnvironment::Mainnet, opt_in);
            assert!(
                m.should_invoke(),
                "MainNet must invoke the gate for opt_in={opt_in}"
            );
            assert_ne!(
                m,
                RatificationGateDecision::Skip(GateSkipReason::DevnetNoOperatorOptIn)
            );
        }
    }

    #[test]
    fn label_is_stable_for_operator_logs() {
        // Operator log lines depend on these strings; pin them so a
        // rename here is caught in review.
        assert_eq!(
            RatificationGateDecision::Invoke(GateInvokeReason::MainnetDefaultStrict).label(),
            "mainnet-default-strict"
        );
        assert_eq!(
            RatificationGateDecision::Invoke(GateInvokeReason::TestnetDefaultStrict).label(),
            "testnet-default-strict"
        );
        assert_eq!(
            RatificationGateDecision::Invoke(GateInvokeReason::DevnetOperatorOptIn).label(),
            "devnet-operator-opt-in"
        );
        assert_eq!(
            RatificationGateDecision::Skip(GateSkipReason::DevnetNoOperatorOptIn).label(),
            "devnet-no-operator-opt-in"
        );
    }
}