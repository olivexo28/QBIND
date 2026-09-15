//! Dormant standard-network runtime/wire alias mapping (Run 422 D7-C3A).
//!
//! This module defines a *pure* mapping policy between the three standard QBIND
//! network environments and a compact 32-bit wire alias. It reuses the existing
//! [`NetworkEnvironment`] and [`ChainId`] definitions from [`crate::primitives`]
//! rather than duplicating the full 64-bit runtime constants in a parallel
//! registry.
//!
//! # Scope and status
//!
//! The wire aliases defined here are **newly defined dormant assignments**. They
//! are NOT existing deployed protocol values, and this module does NOT integrate
//! the policy into message construction, genesis authority, signing, verification
//! or production activation. It only defines and (via tests) exercises the
//! mapping.
//!
//! # Policy
//!
//! | Environment | Authoritative runtime ChainId        | Wire alias   |
//! |-------------|--------------------------------------|--------------|
//! | DevNet      | [`NetworkEnvironment::chain_id`]      | `0x44455600` |
//! | TestNet     | [`NetworkEnvironment::chain_id`]      | `0x54535400` |
//! | MainNet     | [`NetworkEnvironment::chain_id`]      | `0x4D41494E` |
//!
//! The authoritative expected runtime ID for each environment is obtained
//! exclusively from [`NetworkEnvironment::chain_id`]; the wire alias is the only
//! new constant introduced per network.

use crate::primitives::{ChainId, NetworkEnvironment};

/// A dormant, wire-level 32-bit alias identifying a standard QBIND network.
///
/// This is a compact tag distinct from the full 64-bit runtime [`ChainId`]. It
/// carries no protocol meaning yet; see the module documentation for scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NetworkWireAlias(pub u32);

impl NetworkWireAlias {
    /// Get the raw `u32` value of the wire alias.
    pub const fn as_u32(&self) -> u32 {
        self.0
    }
}

impl std::fmt::Display for NetworkWireAlias {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "wire_alias_{:08x}", self.0)
    }
}

/// Dormant wire alias for QBIND DevNet.
pub const QBIND_DEVNET_WIRE_ALIAS: NetworkWireAlias = NetworkWireAlias(0x44455600);

/// Dormant wire alias for QBIND TestNet.
pub const QBIND_TESTNET_WIRE_ALIAS: NetworkWireAlias = NetworkWireAlias(0x54535400);

/// Dormant wire alias for QBIND MainNet.
pub const QBIND_MAINNET_WIRE_ALIAS: NetworkWireAlias = NetworkWireAlias(0x4D41494E);

/// Error returned when a supplied runtime [`ChainId`] does not match the
/// authoritative expected runtime for the selected [`NetworkEnvironment`].
///
/// The expected runtime is always [`NetworkEnvironment::chain_id`]; this error
/// therefore captures a caller-supplied/runtime mismatch rather than a mapping
/// inconsistency.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkWireAliasMismatch {
    /// The environment that was selected by the caller.
    pub environment: NetworkEnvironment,
    /// The authoritative expected runtime ID (`environment.chain_id()`).
    pub expected_runtime: ChainId,
    /// The runtime ID that was actually supplied by the caller.
    pub supplied_runtime: ChainId,
}

impl std::fmt::Display for NetworkWireAliasMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "network wire alias mismatch for {}: expected runtime {}, supplied {}",
            self.environment, self.expected_runtime, self.supplied_runtime
        )
    }
}

impl std::error::Error for NetworkWireAliasMismatch {}

/// Resolve the dormant wire alias for a standard network.
///
/// This is a *pure* helper: given a selected [`NetworkEnvironment`] and a
/// caller-supplied full [`ChainId`], it verifies that the supplied runtime ID
/// equals the authoritative expected runtime ([`NetworkEnvironment::chain_id`]),
/// then returns the wire alias assigned to that environment.
///
/// Returns [`NetworkWireAliasMismatch`] when the supplied runtime ID does not
/// match the environment's authoritative runtime ID.
pub fn resolve_network_wire_alias(
    environment: NetworkEnvironment,
    supplied_runtime: ChainId,
) -> Result<NetworkWireAlias, NetworkWireAliasMismatch> {
    let expected_runtime = environment.chain_id();
    if supplied_runtime != expected_runtime {
        return Err(NetworkWireAliasMismatch {
            environment,
            expected_runtime,
            supplied_runtime,
        });
    }

    Ok(match environment {
        NetworkEnvironment::Devnet => QBIND_DEVNET_WIRE_ALIAS,
        NetworkEnvironment::Testnet => QBIND_TESTNET_WIRE_ALIAS,
        NetworkEnvironment::Mainnet => QBIND_MAINNET_WIRE_ALIAS,
    })
}
