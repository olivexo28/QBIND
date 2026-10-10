# Independent full-source review — RUN 422 D7-D14 (OPEN)

This arm is the required **independent full-source review** of the frozen storage
candidate. It is **OPEN**. Implementation-agent self-assessment and a documentation-diff
review do **not** discharge this gate.

## 1. Review target (the full frozen source, not a diff)

- **Frozen implementation/test candidate:** `aad0a4aaca8f66580d257c3468f1c27059145dbd`
- **Candidate tree:** `82caed801176b243beda89ad07e5a7376fe958e9`
- The candidate is byte-identical to this branch's HEAD across every implementation,
  test, `Cargo`, lockfile, configuration, and CI blob (see `../README.md`, `manifests/`),
  so only documentation differs on the branch — the implementation itself is **not** in
  the branch diff and must be reviewed from the fixed revision's **full source**.

### Component source (nine files) — to be reviewed in full

- `crates/qbind-node/src/safety_record_store/accounting.rs`
- `crates/qbind-node/src/safety_record_store/backend.rs`
- `crates/qbind-node/src/safety_record_store/codec.rs`
- `crates/qbind-node/src/safety_record_store/error.rs`
- `crates/qbind-node/src/safety_record_store/mod.rs`
- `crates/qbind-node/src/safety_record_store/owner.rs`
- `crates/qbind-node/src/safety_record_store/profile.rs`
- `crates/qbind-node/src/safety_record_store/record.rs`
- `crates/qbind-node/src/safety_record_store/validate.rs`

Per-file SHA-256 in `manifests/component_sha256.txt`; blob SHAs in
`manifests/component_blob_shas.txt`.

### Relevant callers / dependencies and the acceptance test

- The owner mutation surface (`owner.rs`: `attach`, `initialize`/O1, `open`/O2,
  `read_validate`/O3, `publish_locked`/O4, `reacknowledge`/O5) and the backend it binds
  (`backend.rs`), including the `#[cfg(any(test, feature = "test-utils"))]`-gated debug
  helpers, must be inspected together with the module's public re-export surface
  (`crates/qbind-node/src/lib.rs`).
- **D7-D14 integration/acceptance test:**
  `crates/qbind-node/tests/run_422_d7d14_safety_record_store_tests.rs`.

### Applicable contract requirements

- `docs/protocol/QBIND_CONSENSUS_RECOVERY_SIGNING_HISTORY_CORRESPONDENCE_CONTRACT.md`
  **§13.8A** (adopted evidence methods for H7 and H16) and **§13.9** (existing-vs-missing
  scope exclusions and the single-successor verdict). The reviewer must assess the
  candidate against these, not only against the branch diff.

## 2. Preserved evidence available to the reviewer

- **A/B security-suite SARIF** (lossless gzip, complete metadata/invocations/diagnostics/
  related-locations/traces/all workspace results):
  - `sarif/A_production_default.sarif.gz` — Config A (production default:
    `rust.cargo_features=default`, `rust.cargo_cfg_overrides=-test`, cfg(test) disabled);
    50 workspace / 2 component results.
  - `sarif/B_acceptance_testutils.sarif.gz` — Config B (acceptance:
    `rust.cargo_features=default,qbind-node/test-utils`, cfg(test) enabled);
    828 workspace / 50 component results.
  - Compressed and decompressed SHA-256 in `logs/checksums.txt` (both verified
    byte-identical and checksum-matching in this pass).
- **Dispositions:** `results/dispositions.csv` / `.json` — all **52** component-scoped
  result mappings, each with explicit `reported_level` (`warning`) and `security_severity`
  (`7.5`) fields read from the preserved SARIF, inspected evidence, disposition, and
  rationale. The only component-scoped rule is `rust/cleartext-logging`; each result is
  dispositioned a per-location false positive on inspected non-sensitive values, a
  conclusion kept **separate** from the rule's reported severity metadata.
- **Supplementary diagnostic assessment** (`diagnostics/`, run on rebuilt databases,
  distinct from the security-suite executions): type-inference consistency queries locate
  the two error-level "Ill-formed type mention" results as tuple arguments to
  `std::any::type_name` in two standalone example helpers
  (`examples/run_259_…:2091`, `examples/run_261_…:1862`) — not the component, not the
  D7-D14 test, not relevant callers/dependencies; scoped conclusion: not a
  storage-component defect. `diagnostics/qlpack.yml` pins `codeql/rust-all: 0.2.23`.

## 3. Known analyzer limitations and inherited test execution (kept separate)

- **Analyzer limitations.** Config B reaches the extractor's per-file diagnostic cap for
  the D7-D14 test file; the suppressed contents are **not recoverable** from the preserved
  SARIF and are **not** asserted benign. The unresolved `$crate::panic::panic_2021` at
  test line 5324 is an analyzer macro-expansion limitation, **not** a Rust test failure.
  Function presence and resolved-call counts support, but do **not** prove, complete
  semantic/data-flow coverage.
- **Inherited test execution.** Previously recorded integration/unit test outcomes are
  **inherited** and attributed to their producing executions; they are **not** re-run here
  and are kept distinct from the CodeQL analyzer coverage above.

## 4. Why this arm is still OPEN

The review interfaces reachable from this environment are **diff-scoped**: they review the
current branch's staged/unstaged/branch change set (the same change set surfaced to PR Code
Review) and do **not** accept an arbitrary fixed commit plus its full source tree as an
independent-review target. Because the branch diff is documentation-only, a diff-scoped
reviewer would see only the documentation files — not the `safety_record_store`
implementation, its callers, or the acceptance tests — and therefore cannot discharge the
independent review of the component source. The implementation agent's self-assessment is
explicitly **insufficient** for this gate. No people were contacted and no source was
transmitted to any new external service; the unavailable review wrapper was **not**
re-invoked merely to obtain another "no comments" summary.

## 5. Required reviewer output (to close this arm)

An independent reviewer targeting the **fixed revision's full source** (the nine component
files, the relevant callers/dependencies, and the D7-D14 acceptance test above) against
contract §13.8A / §13.9 must return:

1. The **reviewed revision** (commit + tree) and the **inspected scope** (files/surfaces).
2. **Findings** with concrete source references (file:line).
3. **Dispositions** for each finding (and concurrence or dissent on the 52 preserved
   CodeQL dispositions).
4. **Remaining limitations** and any obligations left not demonstrated.

## 6. Next executable action

Route the fixed revision `aad0a4a` full component source (plus callers and
`run_422_d7d14_safety_record_store_tests.rs`) and the §13.8A / §13.9 requirements to a
reviewer interface that supports fixed-revision, full-source targeting (independent of the
working-branch diff). Until such an interface is available, this arm remains **OPEN**; the
CodeQL A/B arm stands on its own preserved evidence and does not promote any global
acceptance verdict.