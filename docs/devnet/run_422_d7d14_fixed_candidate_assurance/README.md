# RUN 422 D7-D14 — Fixed-Candidate CodeQL Assurance (Ondrat / QBIND)

> **Continuation correction (D7-D14 configuration-coverage / artifact-preservation
> pass).** Two operative claims recorded in earlier revisions of this directory are
> **corrected** here; the historical execution record is preserved, not relabelled.
> (1) The earlier inference that two databases demonstrated *configuration-independent
> extraction* is **withdrawn**: in the official CodeQL extractor at tag
> `codeql-cli/v2.27.2`, `rust/extractor/src/config.rs` `to_cfg_overrides` seeds
> `enabled_cfgs` with `test` **by default** (L253), and only a `-`-prefixed spec
> (`-test`) disables a cfg (L256–259). The second database's
> `rust.cargo_cfg_overrides=test` therefore left `test` **enabled** (identical to the
> default) and did **not** establish a test-disabled comparison; matching function
> counts and rounded relation sizes do not prove identical semantic databases. The
> production-default (test-disabled) and the explicit acceptance-test (`test-utils`)
> configurations are consequently **not yet demonstrated** — see the remaining-gap
> note below. (2) The ~6 MiB full-workspace SARIF was preserved only under the
> temporary path `/tmp/run422_d7d14/sarif/`, which is **not** durable preservation and
> is **absent** in this continuation sandbox; its recorded SHA-256 could **not** be
> re-verified here. See `logs/checksums.txt` and the Run 422 D7-D14 continuation entry
> in `../QBIND_DEVNET_EVIDENCE_RUN_422_D7.md`.

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
| Latest reviewed assurance revision (commit) | `b826454a95b77db5c541305e41d1a0ed7de72a1b` |

`aad0a4a^{tree} == 82caed80` (verified). The analysis was performed on a detached
worktree checked out at `aad0a4a`, i.e. the exact candidate tree. (An earlier
revision of this table cited `b8278d89…` as the reviewed revision; the operative
reviewed assurance revision is `b826454…`, corrected here.)

## Source boundary (as executed)

- Branch (actual, as supplied): `copilot/copilotrun-422-d7-d14-please-work`;
  upstream `origin/<same>`. (The reported branch `copilot/run-422-d7-d14-please-work`
  is a stale label; the supplied task branch is used as-is and not renamed.)
- Historical analysis-time HEAD: `1d5d1eb` (tree `7b248452`). The continuation
  correction pass runs from a sibling HEAD `8d0fcce` (parent `1d5d1eb`), which is a
  sibling — not a descendant — of the reviewed assurance revision `b826454` (also a
  child of `1d5d1eb`); both added this assurance directory on top of `1d5d1eb`.
- The HEAD "update" commit over `1d5d1eb` carried no code-tree change; starting-tree
  correspondence is attributed to the named HEAD, not to any later
  documentation-only commit, and is kept separate from the final HEAD after this
  pass's evidence commits.
- `aad0a4a` (candidate) vs HEAD differ **only** in documentation files
  (`QBIND_DEVNET_EVIDENCE_RUN_422_D7.md`,
  `QBIND_CONSENSUS_RECOVERY_SIGNING_HISTORY_CORRESPONDENCE_CONTRACT.md`,
  `contradiction.md`, and this `run_422_d7d14_fixed_candidate_assurance/` tree).
  Every implementation, test, `Cargo.toml`, `Cargo.lock`, configuration, and CI blob
  is byte-identical between candidate and HEAD (`manifests/component_sha256.txt`
  re-verified: all ten files OK).
- The named objects were absent from the shallow clone and fetched by SHA with
  `git fetch origin <sha>`.

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
  **[Correction — inference withdrawn.]** The second DB does **not** establish a
  configuration-independent or test-disabled comparison: at `codeql-cli/v2.27.2`,
  `rust/extractor/src/config.rs` `to_cfg_overrides` seeds `test` into `enabled_cfgs`
  by default (L253) and removes a cfg only when the spec is `-`-prefixed (L256–259).
  `rust.cargo_cfg_overrides=test` (no `-`) therefore re-enabled an already-enabled
  `test`, yielding an extraction effectively identical to the default; equal function
  counts and rounded relation sizes do **not** prove identical semantic databases.
  Four distinct settings are **not** interchangeable and must be stated separately:
  (a) the extractor's default **all Cargo features enabled**; (b) the project's
  **default** Cargo feature set; (c) explicit **`test-utils`** analysis; and
  (d) **`cfg(test)`** treatment. The production-default configuration requires
  `rust.cargo_features=default` **and** `rust.cargo_cfg_overrides=-test` (with the
  leading `-`) to disable `cfg(test)`; that run and an explicit
  default-plus-`test-utils` run were **not** executed in this bounded continuation
  (see "Configuration-coverage gap" below).
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

The two DB rows above are both **test-enabled** extractions (the second's
`cargo_cfg_overrides=test` did not disable `cfg(test)` — see the extraction
correction). They establish the all-features / test-enabled model, not the
production-default or the explicit `test-utils` model.

## Configuration-coverage gap (remaining limitation)

The successful execution above covers **one** effective configuration: all Cargo
features enabled with `cfg(test)` enabled. Two required configurations are **not yet
demonstrated**, and are recorded as an explicit limitation rather than claimed:

- **A — Production default.** `rust.cargo_features=default` **with**
  `rust.cargo_cfg_overrides=-test` (leading `-` to disable `cfg(test)`), to confirm
  the production semantic model excludes `test-utils` and test-only
  mutation/fault-injection surfaces. Not executed here.
- **B — Acceptance test.** An explicit default-plus-`test-utils` configuration with
  the required `cfg(test)` treatment, with the integration-test target shown to be
  represented in the semantic model (not inferred from source-archive presence).
  The preserved all-features run has **not** been shown equivalent to this required
  configuration. Not executed here.

Environment limitation (this continuation sandbox): `codeql` is not on `PATH`, the
prior temporary install under `/tmp/run422_d7d14/` is absent (fresh clone), and the
earlier run required `--ram=12000` against ~13 GiB available. The missing
configuration runs are therefore left as a **named open gap**; no universal "all
configurations covered" claim is made, and the useful completed all-features
analysis is preserved.

## Full-workspace SARIF — durable preservation NOT established

The ~6 MiB full-workspace SARIF (`sarif_full_sha256`
`de7d10f3…601777fa`, 828 workspace / 50 component results) was written only to the
temporary path `/tmp/run422_d7d14/sarif/`. A temporary path plus a recorded checksum
is **not** durable artifact preservation. In this continuation sandbox that path is
**absent**, so the original artifact could **not** be recovered and its recorded
SHA-256 could **not** be re-verified here. The committed, retrievable artifacts in
this directory remain the abbreviated `results/component_scoped_findings.json`
(50 component results, no rule metadata/severity), the workspace rule-count summary,
and the per-config coverage CSVs. The full SARIF (rule metadata, severities,
invocation/execution info, extraction diagnostics, related locations, data-flow
traces, all workspace results) is **not** durably preserved. No new checksum or
execution identity is attributed to any replacement, and the original checksum is
**not** re-attributed. `logs/checksums.txt` records this status.

## Findings (within verified scope)

Workspace totals and component-scoped counts are in
`results/findings_summary_workspace.csv`; the 50 component-scoped results are in
`results/component_scoped_findings.json`.

- **No** high-severity security finding (injection, broken/hard-coded crypto,
  pointer/cert issues) touches the component source.
- Component-scoped: 50 × `rust/cleartext-logging` — 49 in the integration
  **test** file (`println!`/formatting in test assertions) and **1** in
  production source: `safety_record_store/codec.rs:415`. That single production
  hit flags the integer `cert_cap` inside a `debug_assert!` message (verified:
  `codec.rs:413–417`, the `debug_assert!(cert.capacity() == cert_cap, …)` divergence
  message); `cert_cap` is a non-sensitive capacity bound and `debug_assert!` is
  compiled out in release. The **assessment** of this result as a false positive is
  recorded **separately** from the rule's reported severity: the abbreviated
  `component_scoped_findings.json` omits rule metadata/severity, so no severity is
  claimed from it — the reported severity of `rust/cleartext-logging` lives in the
  full SARIF's rule metadata, which is not durably preserved here (above). The 49
  test-file results are dispositioned per-location in the evidence doc's disposition
  table, not solely on the basis that they lie in a test file. Per task scope, the
  implementation and tests were **not** modified to satisfy the analyzer; this is
  recorded for any separately scoped correction decision.

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