# RUN 422 D7-D14 — CodeQL analysis-quality diagnostic investigation

Pinned tooling: CodeQL CLI 2.27.2 (bundle `codeql-bundle-v2.27.2`, SHA-256
`f002864be6dd8d5d7bdb123aaf7291ec8e291012bd9f70b6d2362f730db52aeb`),
`codeql/rust-queries@0.1.44`, library `codeql/rust-all@0.2.23`.
Databases rebuilt from the frozen candidate `aad0a4aaca8f66580d257c3468f1c27059145dbd`
(tree `82caed801176b243beda89ad07e5a7376fe958e9`), source verified byte-identical before analysis.

## Diagnostic queries (reviewable source in this directory)
- `illformed_typemention.ql` — individual results for the error-level
  `rust/diagnostics/type-inference-consistency` "Ill-formed type mention", built on the same
  pinned library `codeql.rust.internal.typeinference.TypeInferenceConsistency`
  (module query predicate `illFormedTypeMention`, which filters `tm.fromSource()`).
- `nonunique_certain.ql` — individual results for "Non-unique certain type information"
  (`nonUniqueCertainType`).
- `qlpack.yml` — pack with `codeql/rust-all` dependency.

Invocation (both configs) — **command template, not a captured log.** The per-query
execution console logs were not preserved; this template records the command shape used.
The query files are in **this** directory (`diagnostics/`); run from the evidence root the
query path is `diagnostics/<query>.ql`:
`codeql query run --ram=<selected> --database=dbs/dbX --additional-packs=. diagnostics/<query>.ql`
Database create A: `-O rust.cargo_features=default -O rust.cargo_cfg_overrides=-test`.
Database create B: `-O rust.cargo_features=default,qbind-node/test-utils` (cfg(test) enabled).

### Dependency pin and resolved-version provenance
The committed `qlpack.yml` pins `codeql/rust-all: 0.2.23` for reproducibility. This pin was
**added by the finishing pass** and does **not** retrospectively prove which library version the
earlier diagnostic execution loaded. Three things are kept distinct: (1) the reported historical
execution environment (CodeQL CLI 2.27.2 bundle); (2) retained evidence of the resolved library —
`../logs/codeql_resolve_packs_rust.txt` shows `codeql/rust-all/0.2.23` present under the
2.27.2 bundle; (3) the pin itself. **No `qlpack.lock.yml` was captured at diagnostic-execution
time** — that is a precise, documented limitation, not reconstructed. No timestamps are invented.

## Type-inference inconsistencies (the "two" reported in both SARIFs)
Both configurations resolve to the SAME two "Ill-formed type mention" results, both
`TupleTypeRepr` nodes, exit code 0:
- `crates/qbind-node/examples/run_259_durable_completion_audit_publication_receipt_release_binary_helper.rs:2091`
- `crates/qbind-node/examples/run_261_durable_completion_audit_receipt_acknowledgement_release_binary_helper.rs:1862`

`nonUniqueCertainType` returned 0 rows in Config A (empty result set). The error-level count of
two therefore corresponds entirely to the two ill-formed tuple-type mentions above.

### Component relevance
Both locations are standalone `examples/` release-binary helper programs. They are NOT in the
reviewed component (`crates/qbind-node/src/safety_record_store/*.rs`), NOT in the D7-D14
acceptance test (`crates/qbind-node/tests/run_422_d7d14_safety_record_store_tests.rs`), and are
not relevant callers or dependencies of the component. The affected nodes are tuple type
expressions local to those example binaries; the type relationship does not participate in the
component's analysis. Classification: a CodeQL type-inference MODEL inconsistency on example-only
tuple mentions — not missing coverage of the component and not a demonstrated implementation
defect. The identical locations across A/B were established by comparing actual results, not
inferred from matching counts.

## Config B diagnostic limit and unresolved macro
- `Too many diagnostic messages` is a per-FILE extractor cap (`rust/diagnostics/extraction-warnings`,
  reported at line 1 of each capped file). Config B additionally caps the D7-D14 integration-test
  file `tests/run_422_d7d14_safety_record_store_tests.rs` and `tests/run_422_d7d3_...`. The SARIF
  message carries no suppressed count and no suppressed contents: the CONTENTS of messages beyond
  the per-file cap are NOT recoverable from the preserved SARIF. We do not claim the suppressed
  items are all benign and do not invent their contents.
- Unresolved macro `$crate::panic::panic_2021` at `run_422_d7d14_safety_record_store_tests.rs:5324`,
  inside the assertion message `aborted child is not a success: {status:?}`. This is an analyzer
  macro-expansion coverage limitation, NOT a Rust test failure. Inherited executed-test evidence
  remains attributed; analyzer coverage and executed-test outcome are kept distinct.

## Does not alter the preserved A/B security SARIF
This diagnostic execution is separate from the preserved A/B security reports; those SARIF files
remain byte-identical.
