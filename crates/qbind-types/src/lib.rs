//! Core on-chain state types for the qbind post-quantum blockchain.

pub mod domain;
pub mod network_wire_alias;
pub mod primitives;
pub mod state_governance;
pub mod state_keyset;
pub mod state_roles;
pub mod state_suite;
pub mod state_validator;

pub use domain::{chain_scope, domain_prefix, DomainKind};
pub use network_wire_alias::{
    resolve_network_wire_alias, NetworkWireAlias, NetworkWireAliasMismatch,
    QBIND_DEVNET_WIRE_ALIAS, QBIND_MAINNET_WIRE_ALIAS, QBIND_TESTNET_WIRE_ALIAS,
};
pub use primitives::*;
pub use state_governance::*;
pub use state_keyset::*;
pub use state_roles::*;
pub use state_suite::*;
pub use state_validator::*;
