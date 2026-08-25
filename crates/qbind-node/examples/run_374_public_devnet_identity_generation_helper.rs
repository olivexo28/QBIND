//! Run 374: stable operator-facing **public DevNet identity-generation and
//! verification** helper.
//!
//! ## Run 375 update
//!
//! Run 375 promoted this workflow into the first-class `qbind-node identity`
//! command (`crate::identity_cli`). To avoid duplicated logic while keeping the
//! Run 374 evidence reproducible, this example is now a **thin wrapper** that
//! forwards its arguments straight to `qbind_node::identity_cli::dispatch`. Its
//! observable behavior — `generate` / `verify` modes, the generated file set,
//! the schema-compatible public identity JSON, the `0600` KEM secret key, the
//! in-memory-only root signing key, and the MainNet/TestNet refusals — is
//! identical to the first-class command surface.
//!
//! Prefer the first-class command for new work:
//!
//! ```text
//!   qbind-node identity generate <env> <role> <outdir> [validator_index]
//!   qbind-node identity verify <leaf_cert_path>
//!   qbind-node identity print-public <identity_dir>
//!   qbind-node identity seed-candidate <identity_dir>
//! ```
//!
//! This helper remains a **release-built example**, not a production runtime
//! path. It adds **no** production source change beyond the shared
//! `identity_cli` module, **no** live deployment, admission-policy change,
//! trust-bundle apply, or wire-format change.

use std::process::exit;

fn main() {
    // Forward everything after the example name to the shared identity command
    // dispatcher. The Run 374 CLI shape (`generate …` / `verify …`) is a subset
    // of the first-class `qbind-node identity` subcommand surface, so the
    // argument vectors line up 1:1.
    let args = std::env::args().skip(1);
    exit(qbind_node::identity_cli::dispatch(args));
}