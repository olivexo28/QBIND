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

// ---------------------------------------------------------------------------
// Run 422 D7-C3A extended coverage matrix (task §3).
//
// The three standard networks with their authoritative runtime `ChainId`
// (`NetworkEnvironment::chain_id()`) and their assigned dormant wire alias.
// The alias value is deliberately the low 32 bits of the runtime `ChainId`;
// this table is the single source used by the matrix tests below.
// ---------------------------------------------------------------------------
const STANDARD_NETWORKS: [(NetworkEnvironment, ChainId, NetworkWireAlias); 3] = [
    (
        NetworkEnvironment::Devnet,
        QBIND_DEVNET_CHAIN_ID,
        QBIND_DEVNET_WIRE_ALIAS,
    ),
    (
        NetworkEnvironment::Testnet,
        QBIND_TESTNET_CHAIN_ID,
        QBIND_TESTNET_WIRE_ALIAS,
    ),
    (
        NetworkEnvironment::Mainnet,
        QBIND_MAINNET_CHAIN_ID,
        QBIND_MAINNET_WIRE_ALIAS,
    ),
];

const LOW_32_MASK: u64 = 0x0000_0000_FFFF_FFFF;

/// A (task §3.E): explicit reasonable upper bound, in bytes, for the rendered
/// `Display` / `Debug` of a mismatch error under extreme supplied values.
const DIAGNOSTIC_MAX_BYTES: usize = 256;

// A. Full 3x3 environment/runtime matrix.
//
// Nine cases: the three diagonal (matching) pairs resolve to the exact assigned
// alias; all six off-diagonal (mismatched) standard-network pairs reject with the
// error carrying the selected environment plus the expected/supplied runtime
// metadata.
#[test]
fn matrix_a_full_3x3_environment_runtime_pairs() {
    for (env, runtime, alias) in STANDARD_NETWORKS {
        // The authoritative expected runtime is taken from chain_id() alone.
        assert_eq!(runtime, env.chain_id());
        for (_other_env, other_runtime, _other_alias) in STANDARD_NETWORKS {
            let result = resolve_network_wire_alias(env, other_runtime);
            if other_runtime == runtime {
                // Matching pair: exact alias.
                assert_eq!(result.expect("matching pair resolves"), alias);
            } else {
                // Mismatched pair: reject with exact metadata.
                let err = result.expect_err("mismatched standard pair rejects");
                assert_eq!(err.environment, env);
                assert_eq!(err.expected_runtime, runtime);
                assert_eq!(err.expected_runtime, env.chain_id());
                assert_eq!(err.supplied_runtime, other_runtime);
            }
        }
    }
}

// B. Boundary / extreme runtime IDs reject under every environment.
//
// ChainId(0), ChainId(u32::MAX as u64), ChainId(u64::MAX) and a representative
// unsupported ID already exercised elsewhere. None coincides with a standard
// runtime (every standard runtime carries the non-zero "QBND" high word).
#[test]
fn matrix_b_boundary_runtime_ids_reject_under_every_environment() {
    let boundary = [
        ChainId(0),
        ChainId(u32::MAX as u64),
        ChainId(u64::MAX),
        ChainId(0x0000_0000_DEAD_BEEF),
    ];
    for (env, runtime, _alias) in STANDARD_NETWORKS {
        for bogus in boundary {
            // Guard: none of these boundary values is a valid standard runtime.
            assert_ne!(bogus, env.chain_id());
            let err = resolve_network_wire_alias(env, bogus)
                .expect_err("boundary runtime id is rejected");
            assert_eq!(err.environment, env);
            assert_eq!(err.expected_runtime, runtime);
            assert_eq!(err.supplied_runtime, bogus);
        }
    }
}

// C. High-bit-flip matrix: identical low 32 bits, changed high bits.
//
// For each standard network, deterministically construct unsupported full
// runtime IDs that keep the low word but change the high 32 bits (a zeroed high
// word, an all-ones high word, and every single high-bit flip). Each variant
// must (1) share the low word, (2) differ as a full 64-bit ID, and (3) reject.
#[test]
fn matrix_c_high_bit_flips_share_low_word_but_reject() {
    for (env, runtime, _alias) in STANDARD_NETWORKS {
        let expected = env.chain_id();
        assert_eq!(expected, runtime);
        let low = (expected.0 & LOW_32_MASK) as u32;

        let mut variants: Vec<u64> = vec![
            // Zeroed high word (low word only).
            low as u64,
            // All-ones high word.
            0xFFFF_FFFF_0000_0000u64 | (low as u64),
        ];
        // Flip each individual high bit (bits 32..=63).
        for bit in 32..64 {
            variants.push(expected.0 ^ (1u64 << bit));
        }

        for full in variants {
            let candidate = ChainId(full);
            // (1) Low words match.
            assert_eq!((candidate.0 & LOW_32_MASK) as u32, low);
            // (2) Full IDs differ.
            assert_ne!(candidate, expected);
            // (3) Resolution rejects with exact metadata.
            let err = resolve_network_wire_alias(env, candidate)
                .expect_err("high-bit variant is rejected");
            assert_eq!(err.environment, env);
            assert_eq!(err.expected_runtime, expected);
            assert_eq!(err.supplied_runtime, candidate);
        }
    }
}

// D. The three assigned aliases are pairwise distinct.
#[test]
fn matrix_d_assigned_aliases_are_pairwise_distinct() {
    let aliases = [
        QBIND_DEVNET_WIRE_ALIAS,
        QBIND_TESTNET_WIRE_ALIAS,
        QBIND_MAINNET_WIRE_ALIAS,
    ];
    for i in 0..aliases.len() {
        for j in (i + 1)..aliases.len() {
            assert_ne!(aliases[i], aliases[j], "aliases {i} and {j} collide");
            assert_ne!(aliases[i].as_u32(), aliases[j].as_u32());
        }
    }
}

// E. Extreme supplied values: exact metadata preserved and bounded rendering.
//
// The mismatch error is a fixed-size struct over two `ChainId` values, so its
// `Display` / `Debug` output stays bounded regardless of the magnitude of the
// supplied runtime. Assert both stay within an explicit 256-byte bound while
// still preserving the exact environment / expected / supplied metadata.
#[test]
fn matrix_e_extreme_mismatch_errors_are_bounded_and_preserve_metadata() {
    let extremes = [
        ChainId(0),
        ChainId(u64::MAX),
        ChainId(u32::MAX as u64),
        ChainId(0xFFFF_FFFF_0000_0000),
    ];
    for (env, runtime, _alias) in STANDARD_NETWORKS {
        for supplied in extremes {
            let err = resolve_network_wire_alias(env, supplied)
                .expect_err("extreme supplied value is rejected");
            // Exact metadata preserved.
            assert_eq!(
                err,
                NetworkWireAliasMismatch {
                    environment: env,
                    expected_runtime: runtime,
                    supplied_runtime: supplied,
                }
            );
            let display = err.to_string();
            let debug = format!("{err:?}");
            assert!(
                display.len() <= DIAGNOSTIC_MAX_BYTES,
                "Display exceeds bound: {} bytes",
                display.len()
            );
            assert!(
                debug.len() <= DIAGNOSTIC_MAX_BYTES,
                "Debug exceeds bound: {} bytes",
                debug.len()
            );
            // Identifying environment still present in the rendered diagnostic.
            assert!(display.contains(&env.to_string()), "missing env: {display}");
        }
    }
}
