# RUN 422 D7-D14 — Fixed-Candidate CodeQL Assurance (Ondrat / QBIND)

Bounded evidence for the assurance-execution pass over the **frozen** D7-D14
`safety_record_store` candidate. The implementation was **not** modified; this
directory records provisioning, Rust extraction, security-query execution,
coverage verification, and the independent-review arm. No tools, CodeQL
databases, build caches, dependencies, or secrets are committed.

## Fixed inputs

| Role | Revision |
| --- | --- |
| Implementation/test candidate (commit) | `aad0a4aaca8f66580d257c3468f1c27059145dbd` |
| Candidate tree | `82caed801176b243beda89ad07e5a7376fe958e9` |
| Latest reviewed documentation revision (commit) | `b8278d89b41307a6b680f198ac817a6b4367b77b` |

`aad0a4a^{tree} == 82caed80` (verified). The analysis was performed on a detached
worktree checked out at `aad0a4a`, i.e. the exact candidate tree.

## Source boundary (as executed)

- Branch: `copilot/run-422-d7-d14-please-work`; upstream `origin/<same>`.
- Starting HEAD = final HEAD at analysis time: `1d5d1eb` (tree `7b248452`).
- `b8278d8^{tree} == 1d5d1eb^{tree} == 7b248452` — the reviewed documentation
  revision and the working HEAD carry identical trees; the HEAD "update" commit
  is a no-tree-change commit. Starting-tree equality is attributed to the named
  HEAD, not to any later documentation-only commit.
- `aad0a4a` (candidate) vs HEAD differ **only** in three documentation files
  (`QBIND_DEVNET_EVIDENCE_RUN_422_D7.md`,
  `QBIND_CONSENSUS_RECOVERY_SIGNING_HISTORY_CORRESPONDENCE_CONTRACT.md`,
  `contradiction.md`). Every implementation, test, `Cargo.toml`, `Cargo.lock`,
  configuration, and CI blob is byte-identical between candidate and HEAD.
- The named objects were absent from the shallow clone and fetched with
  `git fetch --depth=1 origin <sha>`.

Review requirements input uses the newer documentation revision, including
contract §13.8A and §13.9.

## Tooling provenance

- Official bundle: `github/codeql-action` release **`codeql-bundle-v2.27.2`**
  (CLI **2.27.2**), asset **`codeql-bundle-linux64.tar.gz`**.
- Published SHA-256 and downloaded SHA-256 match (`logs/checksums.txt`).
- Query pack: **`codeql/rust-queries@0.1.44`** (library `codeql/rust-all@0.2.23`).
- Suite: **`codeql/rust-queries:codeql-suites/rust-security-and-quality.qls`**
  (full resolved query list in `logs/suite_resolved_queries.txt`).
- Host: Linux x86_64, 16 GiB RAM, ~85 GiB free disk, Rust 1.99.0 present.
- `codeql` was absent from `PATH` at the start — the expected provisioning
  precondition, not a blocker. Provisioning used only the authorized temporary
  directory; no persistent/system-wide install, no credentials, no CI change.

## Rust extraction & coverage (established)

- Rust uses `build_modes: [none]` — extraction is rust-analyzer-based parsing of
  the whole cargo workspace; no compilation step. See `logs/rust_extractor_options.txt`.
- Default config enables **all** cargo features, so the `test-utils` feature code
  is extracted. `cfg(test)`-gated items are extracted **regardless** of cfg: a
  second database built with `rust.cargo_cfg_overrides=test` produced an
  identical component extraction (identical relation size and identical per-file
  function counts — `results/coverage_functions_*_db.csv`), and `#[cfg(test)]`
  functions (e.g. `profile.rs:534/546/565`) are present in the **default** DB.
- Semantic extraction of the required scope is verified at the **symbol** level
  (not mere archive presence): all nine
  `crates/qbind-node/src/safety_record_store/*.rs` files plus
  `crates/qbind-node/tests/run_422_d7d14_safety_record_store_tests.rs`
  (191 functions) contain extracted `Function` nodes, with **zero** extraction
  errors or `semantic analyzer unavailable` diagnostics in candidate source.
  (The 92 "extracted with errors" / 3755 semantic-unavailable diagnostics are
  all Rust toolchain/stdlib library files under `.rustup/.../rustlib`.)

## Database / query / SARIF outcomes (separate)

| Stage | Outcome |
| --- | --- |
| DB initialization + extraction (default) | SUCCESS (relations 219.94 MiB; `logs/database_create_outcomes.txt`) |
| DB initialization + extraction (cfg(test)) | SUCCESS (identical relations) |
| Finalization / TRAP import | SUCCESS |
| Query execution (security-and-quality.qls) | SUCCESS after raising `--ram` to 12000 (first run at the auto-selected 1080 MiB JVM heap hit OOM and was rerun) |
| SARIF generation | SUCCESS — 909/909 files scanned |

## Findings (within verified scope)

Workspace totals and component-scoped counts are in
`results/findings_summary_workspace.csv`; the 50 component-scoped results are in
`results/component_scoped_findings.json`.

- **No** high-severity security finding (injection, broken/hard-coded crypto,
  pointer/cert issues) touches the component source.
- Component-scoped: 50 × `rust/cleartext-logging` — 49 in the integration
  **test** file (`println!`/formatting in test assertions) and **1** in
  production source: `safety_record_store/codec.rs:415`. That single production
  hit flags the integer `cert_cap` inside a `debug_assert!` message; `cert_cap`
  is a non-sensitive capacity bound and `debug_assert!` is compiled out in
  release. Assessed as a low-severity false positive. Per task scope, the
  implementation and tests were **not** modified to satisfy the analyzer; this
  is recorded for any separately scoped correction decision.

## Independent-review arm — OPEN

The available review interfaces (PR Code Review / the diff-scoped reviewer) are
scoped to the current change set, which here is **documentation-only** (the
implementation is frozen and identical to HEAD, so there is no implementation
diff to review). No available reviewer can take the fixed revision `aad0a4a`
full component source as an independent-review target. The implementation
agent's own assessment does not satisfy the gate, so this arm is left **OPEN**;
see `04_independent_review.md`.

## Scope / verdicts preserved

This CodeQL pass supplies evidence only within its verified extraction/query
scope; it does not prove consensus correctness, cryptographic security, or
public-DevNet readiness. The 23 Covered items under H7/H16, C4/C5 OPEN,
default-disabled/MainNet-refused operation, fail-closed
`CurrentEpochUnavailable`, and the global D7D14/security verdicts are **not**
promoted or changed by this task. The inherited 157 passed / 1 ignored
integration and 3 passed H7 unit results were **not** rerun and remain inherited.

## Directory map

- `logs/` — version, resolve-languages, rust extractor options, resolved suite
  queries, sanitized command transcript, create/analyze outcomes, checksums.
- `manifests/` — candidate-tree git blob SHAs and working-tree SHA-256 of the
  ten in-scope files.
- `results/` — per-file extraction coverage (both configs), workspace findings
  summary, component-scoped findings JSON.