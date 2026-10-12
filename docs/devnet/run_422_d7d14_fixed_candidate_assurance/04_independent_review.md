# Independent full-source review — RUN 422 D7-D14 (COMPLETE)

This arm is the required **independent full-source review** of the frozen storage
candidate. It is now **COMPLETE** as an **AI-assisted internal review** of the fixed
revision's full source (not a documentation diff). The full report is in
`independent_review/00_review_report.md`; this page records the outcome and the residual
limitations that bound it.

**Independence caveat (unchanged gate semantics).** This review is AI-assisted and internal.
It is **not** a human audit and **not** an organizationally-independent security assessment.
No clause mandating human / external / organizationally-independent assurance for this
isolated-component gate was located or is quoted; the difference in assurance level is recorded
as a **limitation on assurance strength**, not as an established unmet contractual obligation.

## 1. Reviewed target and verified source correspondence

- **Frozen implementation/test candidate:** `aad0a4aaca8f66580d257c3468f1c27059145dbd`
- **Candidate tree:** `82caed801176b243beda89ad07e5a7376fe958e9`
- **Reviewed evidence revision:** `ecf4cfdcc36e9438293173d89e44cd819d709ca5`
- **Working branch / HEAD:** `copilot/run-422-restore-evidence-package` / starting HEAD
  `afc0fa1fd8add76e7c75cd7a13b20c06897db8ee`, final HEAD = this continuation's documentation
  commit (branch used as supplied; not renamed). An earlier draft recorded
  `copilot/copilotcopilotrun-422-d7-d14-please-work-again` / `53a2f7c…`; that attribution is
  corrected here.

The candidate commit, candidate tree, and evidence revision were **fetched** (not ancestors
of HEAD; correspondence established by content). All nine component files and the acceptance
test target are **byte-identical** (git blob equality) to the frozen candidate tree, and the
operative §13 contract at HEAD is byte-identical to the evidence revision. The working tree
therefore *is* the frozen source and was reviewed directly — an empty implementation diff did
not block the review.

## 2. Reviewed scope (read in full)

Nine component files (`accounting.rs`, `backend.rs`, `codec.rs`, `error.rs`, `mod.rs`,
`owner.rs`, `profile.rs`, `record.rs`, `validate.rs`), the acceptance target
`crates/qbind-node/tests/run_422_d7d14_safety_record_store_tests.rs`, and the operative §13
contract (structural/semantic/ownership/accounting/acceptance obligations, including the
adopted §13.8A H7/H16 evidence methods and §13.9 exclusions). Additional files traced:
`crates/qbind-node/src/lib.rs`, `crates/qbind-node/Cargo.toml` (`test-utils` gating), and the
preserved CodeQL evidence under this directory.

## 3. Outcome

- **Confirmed component defects:** **NONE** within the accepted isolated-component scope
  (H2–H12, H16, H18–H25, H26, H27, H30). The ownership, recovery-lifecycle, validation,
  codec, accounting, and failure-handling logic are defensively sound against the §13
  obligations; no source-derived counterexample was found.
- **Newly executed verification (this review):** a fresh build from the frozen source ran a
  focused subset of the acceptance suite — **26 passed / 0 failed / 0 ignored** (covering H7,
  H8b, H10/H11 recovery, H12, H19, H20, H26, H27, H30, the O5 measurement/charge family, and
  the child-process `pd_*` tests). The previously reported **157 passed / 1 ignored**
  integration result and the 3-passed H7 unit result remain **inherited** and are not
  promoted to newly executed.
- **CodeQL dispositions (full A/B SARIF inspected):** the restored full A/B SARIF reports
  (CodeQL 2.27.2; workspace results A = 50 / B = 828; `rust/cleartext-logging` rule metadata
  level `warning`, `security-severity 7.5`, CWE-312/359/532) were decompressed and read, and the
  52 component-scoped results (A = 2, B = 50, all `rust/cleartext-logging`, codeflow sources all in
  `codec.rs`, one production `debug_assert!` sink per config at `codec.rs:415`) were checked
  against the disposition tables. I **concur** with all 52 per-location false-positive
  dispositions (the flagged values are public consensus-protocol quantities / synthetic fixtures,
  not secrets), while preserving the rule's reported level `warning` and `security-severity 7.5`,
  the per-location judgment, and the analyzer coverage limitations as **separate** facts.

## 4. Residual limitations that bound this arm

1. **Evidence restored and verified (prior gap closed).** On the supplied branch
   `sarif/A_production_default.sarif.gz`, `sarif/B_acceptance_testutils.sarif.gz`, and
   `diagnostics/FINDINGS.md` were **absent**, and sixteen present checksum-listed artifacts had
   **byte-drifted** (CRLF / final-newline) and failed their recorded hashes. All remained
   retrievable at `ecf4cf…` and have been **restored to exact original bytes** (git blob-identity
   verified); recorded checksums were preserved, not rewritten. After restoration every committed
   checksum passes, compressed and uncompressed SARIF SHA-256 match, both SARIF are valid JSON
   (A = 50 / B = 828 workspace results), and the SARIF contents were inspected. The prior
   "SARIF absent / cannot verify / dangling reference" limitation is therefore **retired**. The
   one residual non-repository item is the CodeQL tooling bundle
   `codeql-bundle-linux64.tar.gz`, which was **not** retrieved; its recorded digest is carried
   as a claim and is **not** asserted reverified. No CodeQL re-execution was performed or needed.
2. **Analyzer limitations (not runtime defects):** per-file extractor diagnostic cap on the
   D7-D14 test file; unresolved `$crate::panic::panic_2021` macro at test line 5324;
   supplementary-query provenance limits; example-only `type_name` "Ill-formed type mention"
   results in two standalone `examples/` helpers (not the component/test/callers).
3. **Assurance-level limitation** (AI-assisted internal review; not a human /
   organizationally-independent audit — recorded as a limitation, not an unmet obligation; see
   caveat above).
4. **Out of scope (kept separate, not findings):** production engine/decision wiring,
   stage-2 cryptographic verification, durable anti-rollback, activation/launch, and
   release-binary configured-authority evidence — the §13.9-excluded rows (H1, H13–H15, H17,
   H25e, H26l, H28, H29).

## 5. Acceptance recommendation

This review supports a subsequent **isolated-component** acceptance decision for the accepted
23-row subset **on the inspected source, the restored and verified CodeQL evidence, and the
earlier focused-test execution**. The prior SARIF-availability proviso is **satisfied** (the A/B
SARIF are restored, byte-exact, and content-inspected); the only residual qualifier is the
assurance-level limitation (AI-assisted internal vs. human/organizationally-independent), recorded
as a limitation rather than an unmet obligation. It
does **not** support production integration, stage-2 verification, durable anti-rollback,
activation, or launch; those remain separate later gates. All global verdicts are preserved
unchanged: `D7D14_STORAGE_COMPONENT=PARTIAL-IMPLEMENTATION`;
`D7D14_STORAGE_ACCEPTANCE=INCOMPLETE`; `DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`;
`GENESIS_AUTHORITY_ACTIVATION=DISABLED`; `PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`;
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`;
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`; C4/C5 OPEN; H22 separately limited;
default-disabled / MainNet-refused operation, unverified recovered evidence, and fail-closed
`CurrentEpochUnavailable` preserved.