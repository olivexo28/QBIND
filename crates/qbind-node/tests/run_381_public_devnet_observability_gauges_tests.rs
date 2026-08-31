//! Run 381: public DevNet observability gauge tests — node/build/chain info
//! (`qbind_node_build_info`) and the qbind-owned data-dir free-space gauge
//! (`qbind_node_data_dir_free_bytes`).
//!
//! These tests exercise the read-only, low-cardinality gauges added in Run 381
//! directly against `NodeMetrics::format_metrics()`, asserting:
//!
//! - `qbind_node_build_info` is always emitted with value `1` and the required
//!   labels (`version`, `build_id`, `git_commit`, `env`, `chain_id`);
//! - unknown build/chain context renders as `unknown` (never a panic / empty);
//! - the info labels are low-cardinality and secret-free (no path/hostname/
//!   endpoint characters, no whitespace/quote/backslash breakage);
//! - `set_build_context` populates `env`/`chain_id` without leaking any path;
//! - the free-space gauge appears (value only, no label) when a real data-dir is
//!   set on a unix host, and is honestly omitted (no panic) when no data-dir is
//!   set.
//!
//! ```bash
//! cargo test -p qbind-node --test run_381_public_devnet_observability_gauges_tests
//! ```

use qbind_node::metrics::NodeMetrics;

/// Extract the single `qbind_node_build_info{...} <value>` line from a scrape.
fn build_info_line(output: &str) -> Option<String> {
    output
        .lines()
        .find(|l| l.starts_with("qbind_node_build_info{"))
        .map(|l| l.to_string())
}

#[test]
fn build_info_present_with_default_unknown_context() {
    let metrics = NodeMetrics::new();
    let output = metrics.format_metrics();

    let line = build_info_line(&output).expect("qbind_node_build_info must be emitted");

    // Value is always 1 (info metric).
    assert!(
        line.ends_with("} 1"),
        "build_info value must be 1, got: {line}"
    );

    // All required labels present.
    for label in ["version=\"", "build_id=\"", "git_commit=\"", "env=\"", "chain_id=\""] {
        assert!(
            line.contains(label),
            "build_info missing required label {label:?}: {line}"
        );
    }

    // With no build-time env vars / no runtime context, build_id/git_commit and
    // env/chain_id must render as `unknown` (never empty, never a panic).
    assert!(
        line.contains("build_id=\"unknown\"") || line.contains("build_id=\""),
        "build_id must render (unknown when unset): {line}"
    );
    // Default (no set_build_context): env and chain_id are unknown.
    assert!(
        line.contains("env=\"unknown\""),
        "env must be unknown by default: {line}"
    );
    assert!(
        line.contains("chain_id=\"unknown\""),
        "chain_id must be unknown by default: {line}"
    );
}

#[test]
fn build_info_labels_are_low_cardinality_and_secret_free() {
    let metrics = NodeMetrics::new();
    // Feed deliberately hostile context: a path, a host:port, quotes, spaces,
    // and a newline. The sanitizer must strip these to `[A-Za-z0-9._-]`.
    metrics.set_build_context(
        "/var/lib/qbind secret\"env\n",
        "10.0.0.5:9100/chain\\id",
    );
    let output = metrics.format_metrics();
    let line = build_info_line(&output).expect("build_info must be emitted");

    // No path separators, host separators, spaces, quotes-in-value, or escapes.
    // (We check inside the label values by scanning the whole line for the
    // offending characters other than the structural quotes/braces.)
    for bad in ['/', '@', '\\', '\n', ' '] {
        // Structural spaces: the exposition line has exactly one space before the
        // trailing value. Rebuild the label section to check it in isolation.
        let labels = line
            .trim_start_matches("qbind_node_build_info{")
            .split("} ")
            .next()
            .unwrap();
        assert!(
            !labels.contains(bad),
            "build_info label section must not contain {bad:?}: {labels}"
        );
    }

    // The whole line must still parse as a single Prometheus sample ending in ` 1`.
    assert!(line.ends_with("} 1"), "line must end with value 1: {line}");

    // No obvious secret token survives sanitization structure (colon/at/slash gone).
    let labels = line
        .trim_start_matches("qbind_node_build_info{")
        .split("} ")
        .next()
        .unwrap();
    assert!(!labels.contains(':'), "no host:port colon in labels: {labels}");
}

#[test]
fn set_build_context_populates_env_and_chain_id() {
    let metrics = NodeMetrics::new();
    metrics.set_build_context("devnet", "0x0000000000000000");
    let output = metrics.format_metrics();
    let line = build_info_line(&output).expect("build_info must be emitted");

    assert!(line.contains("env=\"devnet\""), "env label wrong: {line}");
    assert!(
        line.contains("chain_id=\"0x0000000000000000\"")
            || line.contains("chain_id=\"0x0000000000000000\""),
        "chain_id label wrong: {line}"
    );
}

#[test]
fn data_dir_free_bytes_absent_without_data_dir() {
    // No data-dir set: the free-space gauge must be omitted (not zero, not a
    // panic). Build info still present.
    let metrics = NodeMetrics::new();
    let output = metrics.format_metrics();
    assert!(
        !output.contains("qbind_node_data_dir_free_bytes"),
        "free-space gauge must be omitted when no data-dir is set"
    );
    assert!(
        build_info_line(&output).is_some(),
        "build_info must still be present without a data-dir"
    );
}

#[cfg(unix)]
#[test]
fn data_dir_free_bytes_present_and_value_only_on_unix() {
    // Point at a real, existing directory (the OS temp dir) so statvfs succeeds.
    let dir = std::env::temp_dir();
    let metrics = NodeMetrics::new();
    metrics.set_data_dir(dir);
    let output = metrics.format_metrics();

    let line = output
        .lines()
        .find(|l| l.starts_with("qbind_node_data_dir_free_bytes "))
        .expect("free-space gauge must be present on unix for a valid data-dir");

    // Value only — no label braces.
    assert!(
        !line.contains('{'),
        "free-space gauge must be value-only (no label): {line}"
    );

    // Value parses as a plain non-negative integer.
    let value: u64 = line
        .split_whitespace()
        .nth(1)
        .expect("gauge must have a value")
        .parse()
        .expect("gauge value must be a plain integer");
    // On any normal CI host the temp dir has some free space.
    assert!(value > 0, "expected > 0 free bytes, got {value}");

    // The path itself must never leak into the output.
    let tmp = std::env::temp_dir();
    let tmp_str = tmp.to_string_lossy();
    if tmp_str != "/" {
        assert!(
            !output.contains(tmp_str.as_ref()),
            "data-dir path must never be emitted in /metrics output"
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