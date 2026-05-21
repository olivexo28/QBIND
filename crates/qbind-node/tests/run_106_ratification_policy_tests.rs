//! Run 106 — integration tests for the **per-environment ratification
//! gate invocation policy** introduced by `qbind_node::pqc_ratification_policy`.
//!
//! These tests pin the Run 106 contract from the operator perspective:
//!
//!   * MainNet ratification enforcement is REQUIRED by default and the
//!     operator opt-in flag can neither enable nor disable it.
//!   * TestNet ratification enforcement is REQUIRED by default; the
//!     operator opt-in flag is informational and cannot disable it.
//!   * DevNet preserves the Run 105 operator-opt-in behaviour so
//!     developer workflows for unsigned/legacy bundles keep working,
//!     and a DevNet skip decision can never appear for MainNet.
//!
//! These tests deliberately exercise ONLY the pure policy helper —
//! they do not stand up a release-binary harness, do not write
//! sequence files, do not start the consensus loop. The gate body
//! itself (`qbind_ledger::enforce_bundle_signing_key_ratification`)
//! is covered by Run 105's integration tests, which Run 106 leaves
//! unchanged.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_106.md`.

use qbind_node::pqc_ratification_policy::{
    ratification_gate_decision, GateInvokeReason, GateSkipReason, RatificationGateDecision,
};
use qbind_types::NetworkEnvironment;

#[test]
fn run_106_mainnet_strict_by_default_without_flag() {
    let d = ratification_gate_decision(NetworkEnvironment::Mainnet, false);
    assert!(d.should_invoke(), "MainNet must invoke the gate by default");
    assert_eq!(
        d,
        RatificationGateDecision::Invoke(GateInvokeReason::MainnetDefaultStrict)
    );
}

#[test]
fn run_106_mainnet_strict_with_flag_is_same_decision() {
    let d = ratification_gate_decision(NetworkEnvironment::Mainnet, true);
    assert!(d.should_invoke());
    assert_eq!(
        d,
        RatificationGateDecision::Invoke(GateInvokeReason::MainnetDefaultStrict)
    );
}

#[test]
fn run_106_testnet_strict_by_default_without_flag() {
    let d = ratification_gate_decision(NetworkEnvironment::Testnet, false);
    assert!(d.should_invoke(), "TestNet must invoke the gate by default");
    assert_eq!(
        d,
        RatificationGateDecision::Invoke(GateInvokeReason::TestnetDefaultStrict)
    );
}

#[test]
fn run_106_devnet_without_opt_in_skips_gate() {
    let d = ratification_gate_decision(NetworkEnvironment::Devnet, false);
    assert!(!d.should_invoke());
    assert_eq!(
        d,
        RatificationGateDecision::Skip(GateSkipReason::DevnetNoOperatorOptIn)
    );
}

#[test]
fn run_106_devnet_with_opt_in_invokes_gate() {
    let d = ratification_gate_decision(NetworkEnvironment::Devnet, true);
    assert!(d.should_invoke());
    assert_eq!(
        d,
        RatificationGateDecision::Invoke(GateInvokeReason::DevnetOperatorOptIn)
    );
}

#[test]
fn run_106_devnet_skip_decision_is_never_returned_for_mainnet_or_testnet() {
    // Defense-in-depth: the DevNet skip decision must be unreachable
    // for MainNet/TestNet across every flag combination.
    for opt_in in [false, true] {
        let m = ratification_gate_decision(NetworkEnvironment::Mainnet, opt_in);
        assert_ne!(
            m,
            RatificationGateDecision::Skip(GateSkipReason::DevnetNoOperatorOptIn),
            "MainNet (opt_in={opt_in}) must not return DevNet skip decision"
        );
        let t = ratification_gate_decision(NetworkEnvironment::Testnet, opt_in);
        assert_ne!(
            t,
            RatificationGateDecision::Skip(GateSkipReason::DevnetNoOperatorOptIn),
            "TestNet (opt_in={opt_in}) must not return DevNet skip decision"
        );
    }
}

#[test]
fn run_106_decision_labels_are_stable() {
    // The labels appear verbatim in operator log lines; pin them here
    // so accidental renames in the helper are caught by a test that
    // explicitly references the Run 106 contract, not just the
    // module-local test.
    assert_eq!(
        ratification_gate_decision(NetworkEnvironment::Mainnet, false).label(),
        "mainnet-default-strict"
    );
    assert_eq!(
        ratification_gate_decision(NetworkEnvironment::Testnet, false).label(),
        "testnet-default-strict"
    );
    assert_eq!(
        ratification_gate_decision(NetworkEnvironment::Devnet, true).label(),
        "devnet-operator-opt-in"
    );
    assert_eq!(
        ratification_gate_decision(NetworkEnvironment::Devnet, false).label(),
        "devnet-no-operator-opt-in"
    );
}