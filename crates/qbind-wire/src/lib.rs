pub mod consensus;
pub mod error;
pub mod gov; // governance call_data structs
pub mod io;
pub mod keyset;
pub mod net; // KEMTLS handshake messages
pub mod tx;
pub mod validator; // slashing proof call_data and related wire types // keyset program call_data structs

// Re-export the default consensus suite ID constant for convenience
pub use consensus::DEFAULT_CONSENSUS_SUITE_ID;

// Re-export payload kind constants for T102.1
pub use consensus::{PAYLOAD_KIND_NORMAL, PAYLOAD_KIND_RECONFIG};

// Re-export protocol version constants (M8)
pub use net::{PROTOCOL_VERSION_1, PROTOCOL_VERSION_2};
