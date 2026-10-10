#!/usr/bin/env bash
# RUN 422 D7-D14 — reproducible command transcript (sanitized).
# All tool provisioning and analysis occurred OUTSIDE the repository, under a
# task-specific temporary directory $T (here /tmp/run422_d7d14). No tools,
# databases, or caches are committed.
set -euo pipefail
T=/tmp/run422_d7d14
CAND=aad0a4aaca8f66580d257c3468f1c27059145dbd   # implementation candidate (tree 82caed80...)
CQ="$T/tools/codeql/codeql"

# --- 0. Source boundary ---
git fetch --depth=1 origin "$CAND"
git worktree add --detach "$T/candidate_src" "$CAND"

# --- 1-6. CodeQL provisioning (official github/codeql-action release) ---
REL=codeql-bundle-v2.27.2
BASE="https://github.com/github/codeql-action/releases/download/$REL"
curl -sSL -o "$T/tools/codeql-bundle-linux64.tar.gz"             "$BASE/codeql-bundle-linux64.tar.gz"
curl -sSL -o "$T/logs/codeql-bundle-linux64.tar.gz.checksum.txt" "$BASE/codeql-bundle-linux64.tar.gz.checksum.txt"
( cd "$T/tools" && sha256sum -c "$T/logs/codeql-bundle-linux64.tar.gz.checksum.txt" )   # -> OK
tar -xzf "$T/tools/codeql-bundle-linux64.tar.gz" -C "$T/tools"

"$CQ" version
"$CQ" resolve languages
"$CQ" resolve packs
"$CQ" resolve extractor --language=rust --format=betterjson

# --- 4. Rust database create (build-mode=none; full candidate source) ---
# Default config: ALL cargo features ON (test-utils included), host cfg.
cargo fetch   # pre-resolve dependency graph (crates.io reachable)
"$CQ" database create "$T/db/rust-default" --language=rust --build-mode=none \
      --source-root="$T/candidate_src" --overwrite
# Separate configuration: cfg(test) enabled (for the "test" cfg arm).
"$CQ" database create "$T/db/rust-cfgtest" --language=rust --build-mode=none \
      --source-root="$T/candidate_src" --extractor-option rust.cargo_cfg_overrides=test --overwrite

# --- 4/5. Official Rust security suite + SARIF ---
"$CQ" database analyze "$T/db/rust-default" \
      codeql/rust-queries:codeql-suites/rust-security-and-quality.qls \
      --format=sarifv2.1.0 --output="$T/sarif/rust-default-security-and-quality.sarif" \
      --sarif-add-query-help --no-sarif-minify --ram=12000 -j2