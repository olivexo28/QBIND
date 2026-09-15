//! Run 422 D7-C3A — pure standard-network runtime/wire alias mapping tests.
//!
//! These tests exercise the dormant mapping policy defined in
//! `qbind_types::network_wire_alias`. They confirm the wire alias assignments,
//! that the authoritative expected runtime is `NetworkEnvironment::chain_id()`,
//! and that a supplied runtime mismatch is rejected.

use qbind_types::{
    resolve_network_wire_alias, ChainId, NetworkEnvironment, NetworkWireAlias,
    NetworkWireAliasMismatch, QBIND_DEVNET_CHAIN_ID, QBIND_DEVNET_WIRE_ALIAS,
    QBIND_MAINNET_CHAIN_ID, QBIND_MAINNET_WIRE_ALIAS, QBIND_TESTNET_CHAIN_ID,
    QBIND_TESTNET_WIRE_ALIAS,
};

#[test]
fn wire_alias_constants_hold_dormant_assignments() {
    assert_eq!(QBIND_DEVNET_WIRE_ALIAS, NetworkWireAlias(0x44455600));
    assert_eq!(QBIND_TESTNET_WIRE_ALIAS, NetworkWireAlias(0x54535400));
    assert_eq!(QBIND_MAINNET_WIRE_ALIAS, NetworkWireAlias(0x4D41494E));

    assert_eq!(QBIND_DEVNET_WIRE_ALIAS.as_u32(), 0x44455600);
    assert_eq!(QBIND_TESTNET_WIRE_ALIAS.as_u32(), 0x54535400);
    assert_eq!(QBIND_MAINNET_WIRE_ALIAS.as_u32(), 0x4D41494E);
}

#[test]
fn resolves_devnet_when_runtime_matches() {
    let alias = resolve_network_wire_alias(
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Devnet.chain_id(),
    )
    .expect("matching runtime resolves");
    assert_eq!(alias, QBIND_DEVNET_WIRE_ALIAS);
}

#[test]
fn resolves_testnet_when_runtime_matches() {
    let alias = resolve_network_wire_alias(NetworkEnvironment::Testnet, QBIND_TESTNET_CHAIN_ID)
        .expect("matching runtime resolves");
    assert_eq!(alias, QBIND_TESTNET_WIRE_ALIAS);
}

#[test]
fn resolves_mainnet_when_runtime_matches() {
    let alias = resolve_network_wire_alias(NetworkEnvironment::Mainnet, QBIND_MAINNET_CHAIN_ID)
        .expect("matching runtime resolves");
    assert_eq!(alias, QBIND_MAINNET_WIRE_ALIAS);
}

#[test]
fn expected_runtime_is_network_environment_chain_id() {
    for env in [
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Testnet,
        NetworkEnvironment::Mainnet,
    ] {
        // Reuse env.chain_id() as the authoritative expected runtime ID.
        assert!(resolve_network_wire_alias(env, env.chain_id()).is_ok());
    }
}

#[test]
fn rejects_supplied_runtime_mismatch() {
    // TestNet runtime supplied under a DevNet selection.
    let err = resolve_network_wire_alias(NetworkEnvironment::Devnet, QBIND_TESTNET_CHAIN_ID)
        .expect_err("mismatched runtime is rejected");
    assert_eq!(
        err,
        NetworkWireAliasMismatch {
            environment: NetworkEnvironment::Devnet,
            expected_runtime: QBIND_DEVNET_CHAIN_ID,
            supplied_runtime: QBIND_TESTNET_CHAIN_ID,
        }
    );
}

#[test]
fn rejects_arbitrary_runtime_for_every_environment() {
    let bogus = ChainId(0x0000_0000_DEAD_BEEF);
    for env in [
        NetworkEnvironment::Devnet,
        NetworkEnvironment::Testnet,
        NetworkEnvironment::Mainnet,
    ] {
        let err = resolve_network_wire_alias(env, bogus)
            .expect_err("arbitrary runtime is rejected");
        assert_eq!(err.environment, env);
        assert_eq!(err.expected_runtime, env.chain_id());
        assert_eq!(err.supplied_runtime, bogus);
    }
}

#[test]
fn mismatch_error_displays_runtime_context() {
    let err = resolve_network_wire_alias(NetworkEnvironment::Mainnet, QBIND_DEVNET_CHAIN_ID)
        .expect_err("mismatched runtime is rejected");
    let text = err.to_string();
    assert!(text.contains("MainNet"), "unexpected: {text}");
}