# RUN 422 D7-D14 — Fixed-Candidate CodeQL Assurance (Ondrat / QBIND)

> **Execution pass (D7-D14 configuration-coverage / artifact-preservation).** The two
> previously-open deliverables are now **executed**, not merely corrected. Both required
> CodeQL configurations (A production-default, B acceptance-tests) were run end-to-end
> against the frozen candidate, and their complete SARIF is durably preserved in this
> directory as lossless `.sarif.gz`. The earlier corrections remain accurate and are
> retained as context: (1) in the official extractor at `codeql-bundle-v2.27.2`,
> `cargo_cfg_overrides` seeds `test` **enabled by default**, and only a `-`-prefixed spec
> (`-test`) disables a cfg — so a prior `cargo_cfg_overrides=test` run did **not** disable
> `cfg(test)`. This pass therefore uses the correct forms: Config A passes
> `rust.cargo_features=default` **and** `rust.cargo_cfg_overrides=-test` (cfg(test)
> DISABLED), and Config B passes `rust.cargo_features=default,qbind-node/test-utils`
> (cfg(test) ENABLED by extractor default). (2) The original ~6 MiB full-workspace SARIF
> remains **unrecoverable** (it only ever existed under the temporary `/tmp/run422_d7d14/`
> and is absent in a fresh clone; its SHA-256 is **not** re-verifiable and **not**
> re-attributed). The two SARIFs preserved here are **new executions** with their own
> identities/checksums (`logs/checksums.txt`). See the Run 422 D7-D14 entry in
> `../QBIND_DEVNET_EVIDENCE_RUN_422_D7.md`.

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

> **[Historical — superseded in operative status by "Configuration-coverage — A and B
> EXECUTED" below.]** This subsection records the earlier single-database provisioning and
> the withdrawn cfg-inference from the continuation pass, before Configs A and B were
> executed end-to-end. Its withdrawn inferences are retained for the record; the operative
> configuration coverage, severity metadata, and A=188 / B=191 function counts are stated
> in the executed-A/B sections that follow.

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

## Configuration-coverage — A and B EXECUTED

Both required configurations were executed end-to-end against the frozen candidate
(`effective settings → database creation → extraction/finalization → full query
execution → SARIF generation`). Effective settings were confirmed from the extractor's
own config dump in the build logs.

| Config | `rust.cargo_features` | `rust.cargo_cfg_overrides` | cfg(test) | DB relations | workspace results | component results |
| --- | --- | --- | --- | --- | --- | --- |
| **A — production default** | `default` | `-test` | **disabled** | 250.44 MiB | 50 | 2 |
| **B — acceptance tests** | `default,qbind-node/test-utils` | *(empty → test enabled)* | **enabled** | 284.83 MiB | 828 | 50 |

- **A** confirms the production semantic model **excludes** `test-utils`: the
  `test-utils`-gated helper `set_inject_write_failure` resolves to **0** definitions
  (Config B: **2**), and the D7-D14 integration-test target's calls into the component
  largely do not resolve (18 resolved calls / 12 distinct targets, vs Config B's
  **1857 / 123**). `results/coverage_testutils_helper_*.csv`,
  `results/coverage_resolved_calls_*.csv`.
- **B** confirms the D7-D14 integration-test target **is** represented in the semantic
  model: `test-utils`-gated helper present (2 defs) and 1857 calls from the test file
  resolve into component functions via type inference (`Call.getStaticTarget()`), not
  mere source-archive/AST presence. AST `Function`-node counts for the D7-D14 test file
  are themselves **configuration-sensitive**: Config A parses **188** functions and
  Config B parses **191** (the three additional functions appear once `cfg(test)` is
  enabled under `test-utils`; `results/coverage_functions_A_default.csv`,
  `results/coverage_functions_B_testutils.csv`). AST presence ≠ semantic/data-flow
  coverage, and function presence plus resolved-call counts support — but do **not**
  prove — complete semantic or data-flow coverage.
- Configuration sensitivity is visible directly in the **security-query data-flow**
  output: component `rust/cleartext-logging` results are **2** under A vs **50** under B.

These are **new executions** with their own identities (`logs/checksums.txt`). Config B's
workspace/component totals (828/50) **numerically match** the historical all-features
execution, but a **matching result total does not prove an equivalent semantic model**:
the historical all-features execution and this new Config B execution retain **separate
identities** and separate checksums. Config B is **not** the original artifact, does
**not** reuse the original checksum, and its agreement with the historical totals is
recorded as an observation, not as proof of model equivalence.

## Full-workspace SARIF — durably preserved (A and B); original NOT recovered

Complete SARIF for both executed configurations is durably preserved in this directory
as lossless gzip (rule metadata, severities, invocations, diagnostics, related
locations, data-flow traces, **all** workspace results):

- `sarif/A_production_default.sarif.gz` — 50 workspace results (decompresses + validates
  as JSON; SHA-256 in `logs/checksums.txt`).
- `sarif/B_acceptance_testutils.sarif.gz` — 828 workspace results (likewise verified).

The **original** ~6 MiB all-features SARIF (`de7d10f3…601777fa`, 828/50) existed only
under the temporary `/tmp/run422_d7d14/sarif/` and is **absent** in a fresh clone; no
actual artifact source exists, so it could **not** be recovered and its SHA-256 is
**not** re-verifiable and is **not** re-attributed. Config B is a **new** execution of
the equivalent configuration that preserves that configuration's complete evidence
durably, with its own distinct checksum.

## Findings & per-result dispositions

Workspace totals and component counts for **both** configs are in
`results/findings_summary_workspace.csv`. A machine-readable per-result disposition
table (one row per component-scoped result, covering both A and B) is in
`results/dispositions.csv` and `results/dispositions.json` with columns:
`run/configuration | result identifier | rule | location | reported level (`warning`) |
security severity (`7.5`) | reported severity | inspected evidence | disposition |
rationale`. The explicit `reported_level` and `security_severity` fields carry the rule
metadata read from the preserved full SARIF and are kept separate from the per-location
`disposition`. (52 rows: A = 1 test + 1 production;
B = 49 test + 1 production.) The abbreviated `results/component_scoped_findings.json`
is retained for continuity but is superseded by the full per-config
`results/config{A,B}/component_findings_*.json` (which carry rule id, reported severity,
location, flow source, and message) and the disposition table.

- **Reported rule metadata (stated, not minimized).** Every component-scoped result in
  both configs is the single rule `rust/cleartext-logging`, whose preserved SARIF metadata
  is reported **level `warning`** with **`security-severity` `7.5`** (CVSS-style high band).
  This is the rule's **reported metadata** and is recorded **separately** from the
  per-location dispositions below. Earlier "no high-severity finding" / "low-severity"
  phrasings are **withdrawn** as a misrepresentation of that metadata. No other security
  rule (injection, broken/hard-coded crypto, pointer/cert issues) produces a
  component-scoped result in either config; the narrower disposition conclusion is that
  **each** of the 52 `rust/cleartext-logging` results is a per-location **false positive**
  on inspected non-sensitive values (see below), a disposition that is **scoped to these
  inspected locations** and **subject to the analyzer limitations** recorded in
  `diagnostics/FINDINGS.md` and does **not** downgrade the rule's reported severity.
- The single **production** component hit is `safety_record_store/codec.rs:415` in
  **both** A and B: `rust/cleartext-logging` (reported severity `warning`) on the integer
  `cert_cap` inside a `debug_assert!` divergence message (`codec.rs:413–417`). `cert_cap`
  is a non-sensitive capacity bound and `debug_assert!` is compiled out in release →
  disposed **FALSE_POSITIVE_NON_SENSITIVE**. Reported severity is recorded **separately**
  from this false-positive assessment.
- The **test-file** component hits (49 under B, 1 under A) flow from synthetic
  fixture certificates (`decode_timeout_cert`/`admit_timeout_cert`) and Debug-formatted
  error enums / capacity integers into `panic!`/`assert!`/`println!` **test-assertion
  diagnostics**. Each is disposed per-location by inspecting its flow source and sink
  (not merely because it lies in a test file); none carries secret/key/credential
  material → **FALSE_POSITIVE_NON_SENSITIVE_TEST_DIAGNOSTIC**.
- Per task scope, the implementation and tests were **not** modified to satisfy the
  analyzer; the frozen candidate is byte-identical to the manifest (10/10 OK).

## Independent-review arm — OPEN

The available review interfaces (PR Code Review / the diff-scoped reviewer) are
scoped to the current change set, which here is **documentation-only** (the
implementation is frozen and identical to HEAD, so there is no implementation
diff to review). No available reviewer can take the fixed revision `aad0a4a`
full component source as an independent-review target. The implementation
agent's own assessment does not satisfy the gate, so this arm is left **OPEN**;
see `04_independent_review.md`.

## Separate assurance statuses (this finishing pass)

These are reported **separately** and do not promote any global acceptance verdict:

- **A/B security-suite execution — COMPLETE.** Configs A and B executed end-to-end;
  preserved SARIF unchanged and not re-run.
- **Durable artifact integrity — VERIFIED.** Both `sarif/*.sarif.gz` byte-identical;
  decompressed contents match recorded SHA-256; `logs/checksums.txt` refreshed for changed
  artifacts and extended with diagnostic sources/outputs.
- **Diagnostic assessment & residual limitations — RECORDED.** Example-only ill-formed
  tuple mentions (not a component defect); Config B per-file diagnostic cap (suppressed
  contents unrecoverable, not asserted benign); unresolved `panic_2021` macro at test line
  5324 is an analyzer limitation, not a test failure; missing per-query logs noted precisely.
- **Evidence reconciliation — COMPLETE.** `rust/cleartext-logging` reported metadata
  (level `warning`, `security-severity` `7.5`) stated and kept separate from the 52
  per-location false-positive dispositions; test-file function counts A=188 / B=191;
  equivalent-semantic-model inference withdrawn.
- **Independent full-source review — OPEN.** Not discharged by self-assessment or a
  documentation-diff review.

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