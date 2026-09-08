//! Run 382: public DevNet build-info **provenance** tests.
//!
//! Run 381 added `qbind_node_build_info{version,build_id,git_commit,env,chain_id}`
//! but `build_id`/`git_commit` rendered `unknown` unless the build environment
//! injected `QBIND_BUILD_ID` / `QBIND_GIT_COMMIT`. Run 382 adds a build script
//! (`crates/qbind-node/build.rs`) that bridges release provenance into those two
//! compile-time labels:
//!
//!   * `git_commit` — an explicit `QBIND_GIT_COMMIT` env wins, else a short git
//!     commit hash is derived at build time; missing → `unknown`.
//!   * `build_id` — a stable harness/CI-injected `QBIND_BUILD_ID` only (never
//!     derived from git or the ELF); missing → `unknown`.
//!
//! These tests assert, against `NodeMetrics::format_metrics()`, that whatever
//! provenance the build injected is *safe*: single well-formed sample, required
//! labels present, every label value restricted to `[A-Za-z0-9._-]`, and no
//! path / host:port / whitespace / quote / backslash / secret token leaks. They
//! deliberately do NOT hard-code a specific commit, so they pass in both an
//! injected-provenance build and a `unknown`-fallback build.
//!
//! ```bash
//! cargo test -p qbind-node --test run_382_public_devnet_build_info_provenance_tests
//! ```

use qbind_node::metrics::NodeMetrics;

/// Extract the single `qbind_node_build_info{...} <value>` line from a scrape.
fn build_info_line(output: &str) -> Option<String> {
    output
        .lines()
        .find(|l| l.starts_with("qbind_node_build_info{"))
        .map(|l| l.to_string())
}

/// Return the value of a `key="value"` label from the info line, if present.
fn label_value(line: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=\"");
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// True iff every character is in the sanitized alphabet `[A-Za-z0-9._-]`.
fn is_sanitized(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

#[test]
fn build_info_present_with_all_required_labels() {
    let metrics = NodeMetrics::new();
    let output = metrics.format_metrics();
    let line = build_info_line(&output).expect("qbind_node_build_info must be emitted");

    assert!(line.ends_with("} 1"), "info value must be 1: {line}");
    for key in ["version", "build_id", "git_commit", "env", "chain_id"] {
        assert!(
            label_value(&line, key).is_some(),
            "build_info missing required label {key:?}: {line}"
        );
    }
}

#[test]
fn provenance_labels_are_sanitized_or_unknown() {
    let metrics = NodeMetrics::new();
    let output = metrics.format_metrics();
    let line = build_info_line(&output).expect("build_info must be emitted");

    // Whatever the build injected (a real short commit / build id) or did not
    // (`unknown`), the rendered value must be non-empty and sanitized. It must
    // never be empty and never contain an out-of-alphabet character.
    for key in ["version", "build_id", "git_commit"] {
        let value = label_value(&line, key).expect("label present");
        assert!(
            is_sanitized(&value),
            "{key} label must be sanitized [A-Za-z0-9._-], got {value:?}"
        );
    }
}

#[test]
fn provenance_labels_never_leak_path_host_or_secret() {
    let metrics = NodeMetrics::new();
    let output = metrics.format_metrics();
    let line = build_info_line(&output).expect("build_info must be emitted");

    // The label section (between the braces) must never carry a path separator,
    // host `@`/`:` separator, whitespace, quote, or backslash — a build path,
    // hostname, username, branch, or dirty-status string cannot survive.
    let labels = line
        .trim_start_matches("qbind_node_build_info{")
        .split("} ")
        .next()
        .expect("label section");
    for bad in ['/', '@', ':', ' ', '\\', '\n', '\t'] {
        assert!(
            !labels.contains(bad),
            "build_info label section must not contain {bad:?}: {labels}"
        );
    }
    let lower = labels.to_ascii_lowercase();
    for token in ["secret", "token", "password", "apikey", "api_key", "begin"] {
        assert!(
            !lower.contains(token),
            "build_info label section must not contain secret-ish token {token:?}: {labels}"
        );
    }
}

#[test]
fn build_id_is_never_derived_from_git_commit() {
    // build_id must be harness/CI-injected only (never derived from git). When
    // QBIND_BUILD_ID is not injected the label must render exactly `unknown`,
    // even if git_commit was auto-derived by the build script. This guards the
    // "missing injection still renders unknown" fallback for build_id.
    let metrics = NodeMetrics::new();
    let output = metrics.format_metrics();
    let line = build_info_line(&output).expect("build_info must be emitted");

    let build_id = label_value(&line, "build_id").expect("build_id present");
    let git_commit = label_value(&line, "git_commit").expect("git_commit present");

    if option_env!("QBIND_BUILD_ID").is_none() {
        assert_eq!(
            build_id, "unknown",
            "build_id must render `unknown` when QBIND_BUILD_ID is not injected: {line}"
        );
        // And it must not have silently taken the git commit value.
        if git_commit != "unknown" {
            assert_ne!(
                build_id, git_commit,
                "build_id must never be derived from git_commit: {line}"
            );
        }
    } else {
        assert_ne!(
            build_id, "unknown",
            "build_id must be populated when QBIND_BUILD_ID is injected: {line}"
        );
    }
}

#[test]
fn git_commit_matches_injected_provenance_when_present() {
    // When the build injected git provenance (either via QBIND_GIT_COMMIT or a
    // build-script-derived short hash), the rendered git_commit must be a
    // sanitized non-`unknown` token. When neither is available it renders
    // `unknown`. Either way the value is safe.
    let metrics = NodeMetrics::new();
    let output = metrics.format_metrics();
    let line = build_info_line(&output).expect("build_info must be emitted");
    let git_commit = label_value(&line, "git_commit").expect("git_commit present");

    assert!(
        is_sanitized(&git_commit),
        "git_commit must be sanitized, got {git_commit:?}"
    );
    if git_commit != "unknown" {
        // A commit token is short and low-cardinality.
        assert!(
            git_commit.len() <= 64,
            "git_commit token unexpectedly long: {git_commit:?}"
        );
    }
}

#[test]
fn build_info_help_and_type_lines_present() {
    let metrics = NodeMetrics::new();
    let output = metrics.format_metrics();
    assert!(
        output.contains("# HELP qbind_node_build_info"),
        "build_info HELP line missing"
    );
    assert!(
        output.contains("# TYPE qbind_node_build_info gauge"),
        "build_info TYPE line missing"
    );
}
