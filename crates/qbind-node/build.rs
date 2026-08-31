//! Run 382: release-provenance injection for the `qbind_node_build_info`
//! metric.
//!
//! This build script bridges build-time provenance into the two compile-time
//! `option_env!` labels that `metrics.rs` reads for `qbind_node_build_info`:
//!
//!   * `QBIND_GIT_COMMIT` — the source commit the binary was built from.
//!     Precedence: an explicit `QBIND_GIT_COMMIT` env var (CI / release harness
//!     injection) wins; otherwise we derive a short commit hash from `git` in a
//!     bounded, best-effort way. If neither is available the variable is left
//!     unset so `metrics.rs` renders `git_commit="unknown"`.
//!   * `QBIND_BUILD_ID` — a stable, harness/CI-injected build identity. This is
//!     ONLY ever taken from the environment; it is NEVER derived from git or the
//!     ELF here. If unset it is left unset so `metrics.rs` renders
//!     `build_id="unknown"`. (This is the *metric* build_id label — distinct
//!     from the ELF `.note.gnu.build-id` recorded separately in the binary
//!     provenance docs.)
//!
//! Safety constraints (mirrors Run 381 metric constraints):
//!   * Values are sanitized to `[A-Za-z0-9._-]` and length-capped here, and are
//!     sanitized AGAIN at render time by `sanitize_info_label` in `metrics.rs`.
//!   * We only ever expose a commit hash — never a branch name, dirty/status
//!     string, path, hostname, username, or absolute build path.
//!   * Any failure (no git, command error, non-UTF-8) is swallowed: the label is
//!     left unset and renders `unknown`. The build never panics on provenance.
//!   * No new CLI flag and no runtime behaviour change: this only affects two
//!     compile-time label strings.

use std::process::Command;

/// Sanitize a provenance value to a low-cardinality, secret-free token.
///
/// Restricts to `[A-Za-z0-9._-]`, caps the length, and returns `None` for
/// empty/all-invalid input so the caller can skip emitting the variable (which
/// makes `metrics.rs` fall back to `unknown`).
fn sanitize(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(trimmed.len().min(64));
    for ch in trimmed.chars().take(64) {
        if ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    // Reject an all-placeholder result (e.g. input was only separators).
    if out.chars().all(|c| c == '_') {
        return None;
    }
    Some(out)
}

/// Best-effort short git commit hash for the current source tree.
///
/// Returns `None` (never panics) when `git` is unavailable, the directory is not
/// a work tree, or the command fails. Only the abbreviated commit hash is
/// returned — no branch, tag, remote, path, or dirty-state string.
fn git_short_commit() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    sanitize(&text)
}

fn main() {
    // Re-run when the injected provenance env vars change...
    println!("cargo:rerun-if-env-changed=QBIND_GIT_COMMIT");
    println!("cargo:rerun-if-env-changed=QBIND_BUILD_ID");
    // ...and when the checked-out commit changes (best-effort; safe if absent).
    if let Ok(out) = Command::new("git")
        .args(["rev-parse", "--git-path", "HEAD"])
        .output()
    {
        if out.status.success() {
            if let Ok(head_path) = String::from_utf8(out.stdout) {
                let head_path = head_path.trim();
                if !head_path.is_empty() {
                    println!("cargo:rerun-if-changed={head_path}");
                }
            }
        }
    }

    // git_commit: explicit env injection wins, else derive a short hash.
    let git_commit = std::env::var("QBIND_GIT_COMMIT")
        .ok()
        .and_then(|v| sanitize(&v))
        .or_else(git_short_commit);
    if let Some(commit) = git_commit {
        println!("cargo:rustc-env=QBIND_GIT_COMMIT={commit}");
    }

    // build_id: env/harness injection ONLY (never derived from git or the ELF).
    if let Some(build_id) = std::env::var("QBIND_BUILD_ID")
        .ok()
        .and_then(|v| sanitize(&v))
    {
        println!("cargo:rustc-env=QBIND_BUILD_ID={build_id}");
    }
}