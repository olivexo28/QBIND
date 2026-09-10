//! Run 420 (F3/F4/F8) — production reachability guard for the consensus
//! verification policy.
//!
//! These tests enforce the fail-closed boundary at the *source* level: the
//! production `qbind-node` binary must construct its `BinaryConsensusLoopIo`
//! with [`ConsensusVerificationPolicy::Required`] and must never select the
//! test-only `LocalFixtureUnsigned` bypass. This complements the in-crate
//! behavioural tests (which prove `Required + verification_ctx=None` rejects
//! inbound Proposal/Vote and suppresses outbound Proposal/Vote) by proving the
//! fixture bypass is unreachable from the shipped binary entrypoint.

use std::path::{Path, PathBuf};

fn crate_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn read(name: &str) -> String {
    let path = crate_src().join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Returns true if a trimmed source line is a comment (line- or block-style)
/// and therefore not executable code.
fn is_comment_line(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//") || t.starts_with("/*") || t.starts_with('*')
}

/// The value form used when a `verification_policy` field is *assigned* the
/// fixture bypass. Matching this (rather than the bare identifier) avoids
/// false positives on doc-comment intra-doc links and prose mentions.
const FIXTURE_FIELD_ASSIGN: &str =
    "verification_policy: ConsensusVerificationPolicy::LocalFixtureUnsigned";
const REQUIRED_FIELD_ASSIGN: &str =
    "verification_policy: ConsensusVerificationPolicy::Required";

/// The production binary entrypoint (`main.rs`) must select the `Required`
/// policy for its live consensus loop and must never assign the test-only
/// fixture policy to a `verification_policy` field.
#[test]
fn main_rs_selects_required_and_never_fixture_policy() {
    let src = read("main.rs");
    assert!(
        src.contains(REQUIRED_FIELD_ASSIGN),
        "production main.rs must select ConsensusVerificationPolicy::Required \
         for its BinaryConsensusLoopIo"
    );
    let bad: Vec<usize> = src
        .lines()
        .enumerate()
        .filter(|(_, l)| !is_comment_line(l) && l.contains(FIXTURE_FIELD_ASSIGN))
        .map(|(i, _)| i + 1)
        .collect();
    assert!(
        bad.is_empty(),
        "production main.rs must NEVER assign the test-only \
         LocalFixtureUnsigned bypass policy (offending lines: {bad:?})"
    );
}

/// The production node builder helpers must not select the fixture policy
/// either. Belt-and-braces so a future refactor cannot silently move an
/// unsigned bypass into a production construction path.
#[test]
fn p2p_node_builder_never_selects_fixture_policy() {
    let src = read("p2p_node_builder.rs");
    let bad: Vec<usize> = src
        .lines()
        .enumerate()
        .filter(|(_, l)| {
            !is_comment_line(l)
                && l.contains("ConsensusVerificationPolicy::LocalFixtureUnsigned")
        })
        .map(|(i, _)| i + 1)
        .collect();
    assert!(
        bad.is_empty(),
        "production p2p_node_builder.rs must NEVER select the test-only \
         LocalFixtureUnsigned bypass policy (offending lines: {bad:?})"
    );
}

/// Every *executable* selection of the `LocalFixtureUnsigned` fixture policy in
/// `binary_consensus_loop.rs` must live inside the top-level `#[cfg(test)]`
/// module. This proves the fixture bypass is only ever chosen from test code;
/// production code (everything before `mod tests`) selects `Required`.
#[test]
fn fixture_policy_only_selected_from_test_module() {
    let src = read("binary_consensus_loop.rs");
    // Line index (1-based) at which the top-level test module begins.
    let test_mod_line = src
        .lines()
        .position(|l| l.trim_start() == "mod tests {")
        .expect("binary_consensus_loop.rs has a top-level `mod tests {`")
        + 1;
    let needle = "ConsensusVerificationPolicy::LocalFixtureUnsigned";
    let prod_hits: Vec<usize> = src
        .lines()
        .enumerate()
        .filter(|(i, l)| {
            let line_no = i + 1;
            line_no < test_mod_line && !is_comment_line(l) && l.contains(needle)
        })
        .map(|(i, _)| i + 1)
        .collect();
    assert!(
        prod_hits.is_empty(),
        "LocalFixtureUnsigned is selected in executable non-test code at lines \
         {prod_hits:?}; the fixture bypass must only be selected from the \
         #[cfg(test)] module (starting at line {test_mod_line})"
    );
}
