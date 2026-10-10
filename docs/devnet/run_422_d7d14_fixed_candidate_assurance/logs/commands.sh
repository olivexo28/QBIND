#!/usr/bin/env bash
# RUN 422 D7-D14 — reproducible CodeQL A/B execution transcript (sanitized).
# Host: Linux x86_64, 4 vCPU, 15 GiB RAM (~13 GiB avail), ~85 GiB free disk, Rust 1.99.0.
# Frozen candidate commit aad0a4aaca8f66580d257c3468f1c27059145dbd (tree 82caed80...).
set -euo pipefail

# --- 0. Fetch named objects into the shallow clone, create detached worktree ---
git fetch --depth=1 origin aad0a4aaca8f66580d257c3468f1c27059145dbd
git fetch --depth=1 origin 444bfbe87873388b453cbdc1077f311f4a5e2223
git worktree add --detach "$SRC" aad0a4aaca8f66580d257c3468f1c27059145dbd
# verify: git -C "$SRC" rev-parse HEAD^{tree}  == 82caed801176b243beda89ad07e5a7376fe958e9
# verify: sha256sum -c manifests/component_sha256.txt   (all 10 OK)

# --- 1. Provision official CodeQL bundle v2.27.2 outside the repo ---
curl -sSL -o codeql-bundle-linux64.tar.gz \
  https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.27.2/codeql-bundle-linux64.tar.gz
# verify published SHA-256:
echo "f002864be6dd8d5d7bdb123aaf7291ec8e291012bd9f70b6d2362f730db52aeb  codeql-bundle-linux64.tar.gz" | sha256sum -c
tar xzf codeql-bundle-linux64.tar.gz
export PATH="$PWD/codeql:$PATH"
codeql version                 # 2.27.2
codeql resolve languages | grep rust
codeql resolve qlpacks | grep -E 'rust-queries|rust-all'   # rust-queries@0.1.44, rust-all@0.2.23

# --- 2. Config A — PRODUCTION DEFAULT (default features, cfg(test) DISABLED) ---
codeql database create dbs/dbA --language=rust --source-root="$SRC" \
  -O rust.cargo_features=default \
  -O rust.cargo_cfg_overrides=-test \
  --threads=4 --ram=8000
codeql database analyze dbs/dbA \
  codeql/rust-queries:codeql-suites/rust-security-and-quality.qls \
  --format=sarifv2.1.0 --output=sarif/A_production_default.sarif \
  --sarif-add-snippets --threads=4 --ram=10000

# --- 3. Config B — ACCEPTANCE TESTS (default + qbind-node/test-utils, cfg(test) ENABLED default) ---
codeql database create dbs/dbB --language=rust --source-root="$SRC" \
  -O rust.cargo_features=default,qbind-node/test-utils \
  --threads=4 --ram=8000
codeql database analyze dbs/dbB \
  codeql/rust-queries:codeql-suites/rust-security-and-quality.qls \
  --format=sarifv2.1.0 --output=sarif/B_acceptance_testutils.sarif \
  --sarif-add-snippets --threads=4 --ram=10000

# --- 4. Configuration-sensitive semantic/data-flow coverage (covql pack) ---
#   func_counts.ql       : per-file Function (AST) counts
#   resolved_calls.ql    : Call.getStaticTarget() (type-inference) resolving into component
#   testutils_helper.ql  : presence of test-utils-gated set_inject_write_failure
for db in dbA dbB; do
  codeql query run --database=dbs/$db --additional-packs=codeql covql/func_counts.ql
  codeql query run --database=dbs/$db --additional-packs=codeql covql/resolved_calls.ql
  codeql query run --database=dbs/$db --additional-packs=codeql covql/testutils_helper.ql
done

# --- 5. Preserve full SARIF losslessly + checksums ---
gzip -9 -c sarif/A_production_default.sarif  > sarif/A_production_default.sarif.gz
gzip -9 -c sarif/B_acceptance_testutils.sarif > sarif/B_acceptance_testutils.sarif.gz