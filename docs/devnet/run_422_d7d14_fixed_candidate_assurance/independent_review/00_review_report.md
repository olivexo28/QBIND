# RUN 422 D7-D14 — Independent Full-Source Review Report

**Project:** Ondrat (repository, crate, file, and protocol identifiers retain their QBIND
names). **Component under review:** `qbind_node::safety_record_store` — the isolated,
disabled-by-default safety-record storage candidate. **This document is a review artifact
only.** No implementation, test, Cargo, lockfile, configuration, CI, or protocol-contract
file was changed by this review.

---

## 1. Reviewer role, independence, and limitations

- **Role.** AI-assisted source reviewer acting in a review session separate from the
  implementation session. This review *reads and reasons about the complete frozen source
  tree directly*; it did not require a diff-scoped wrapper or a dedicated review-engine
  binary, and an empty implementation diff did not prevent reviewing the fixed source.
- **Agent/model identification.** GitHub Copilot coding agent (large-language-model
  assisted). The review was performed with repository tooling (git, ripgrep, file reads)
  and a bounded `cargo test` execution described in §6.
- **Separation.** The author of this review is not the implementation author of the frozen
  candidate and made no implementation or test edits. Only the authorized review documents
  listed in §9 were written.
- **Independence limitations (stated explicitly).** This is an **AI-assisted internal
  review**. It is **not** an external human audit and **not** an organizationally
  independent security assessment. If the governing isolated-component acceptance
  requirement demands third-party / human / organizationally-independent assurance, **that
  stronger-independence obligation remains OUTSTANDING and is not discharged by this
  review.** This review assesses implementation reports and CodeQL dispositions as claims;
  it does not merely restate them.

---

## 2. Evidence baseline and source correspondence (independently established)

| Item | Value |
| --- | --- |
| Actual working branch | `copilot/copilotcopilotrun-422-d7-d14-please-work-again` (used as supplied; **not** switched or renamed to match the report's `…please-work`) |
| Starting / final HEAD | `53a2f7cad6111e024f19a48b50fd5a1db788f6d5` |
| Upstream | `origin/copilot/copilotcopilotrun-422-d7-d14-please-work-again` |
| Worktree status (start) | clean |
| Frozen implementation/test candidate | `aad0a4aaca8f66580d257c3468f1c27059145dbd` |
| Candidate tree | `82caed801176b243beda89ad07e5a7376fe958e9` |
| Reviewed evidence revision | `ecf4cfdcc36e9438293173d89e44cd819d709ca5` |

**Object availability.** The candidate commit, candidate tree, and evidence revision were
not present in the shallow single-branch clone and were **fetched** by object id. The
candidate commit's tree equals the stated candidate tree `82caed80…`. Neither the candidate
commit nor the evidence revision is an ancestor of HEAD (verified by merge-base);
correspondence was therefore established by **content**, not ancestry.

**Source correspondence (byte-level, not assumed).** Every one of the nine source files and
the acceptance-test target resolves to a git blob at HEAD that is **identical** to the blob
at the frozen candidate tree `82caed80…`:

```
OK  crates/qbind-node/src/safety_record_store/accounting.rs
OK  crates/qbind-node/src/safety_record_store/backend.rs
OK  crates/qbind-node/src/safety_record_store/codec.rs
OK  crates/qbind-node/src/safety_record_store/error.rs
OK  crates/qbind-node/src/safety_record_store/mod.rs
OK  crates/qbind-node/src/safety_record_store/owner.rs
OK  crates/qbind-node/src/safety_record_store/profile.rs
OK  crates/qbind-node/src/safety_record_store/record.rs
OK  crates/qbind-node/src/safety_record_store/validate.rs
OK  crates/qbind-node/tests/run_422_d7d14_safety_record_store_tests.rs
```

The operative §13 contract file
`docs/protocol/QBIND_CONSENSUS_RECOVERY_SIGNING_HISTORY_CORRESPONDENCE_CONTRACT.md` at HEAD
has blob `90c02fa07201ad64bd24c1495ad1c22d90fabb95`, **identical** to its blob at the
evidence revision `ecf4cf…`. The working tree therefore *is* the frozen source and the
operative contract; the review reads them directly.

---

## 3. Inspected scope (complete enumeration)

**Primary source (read in full):**

- `crates/qbind-node/src/safety_record_store/accounting.rs`
- `crates/qbind-node/src/safety_record_store/backend.rs`
- `crates/qbind-node/src/safety_record_store/codec.rs`
- `crates/qbind-node/src/safety_record_store/error.rs`
- `crates/qbind-node/src/safety_record_store/mod.rs`
- `crates/qbind-node/src/safety_record_store/owner.rs`
- `crates/qbind-node/src/safety_record_store/profile.rs`
- `crates/qbind-node/src/safety_record_store/record.rs`
- `crates/qbind-node/src/safety_record_store/validate.rs`

**Acceptance target (read in full):**

- `crates/qbind-node/tests/run_422_d7d14_safety_record_store_tests.rs` (10,908 lines)

**Operative contract (read for the obligations below, not only §13.8A/§13.9):**

- `docs/protocol/QBIND_CONSENSUS_RECOVERY_SIGNING_HISTORY_CORRESPONDENCE_CONTRACT.md`,
  §13 structural / semantic / ownership / accounting / acceptance obligations, including the
  adopted §13.8A H7/H16 evidence methods and §13.9 exclusions and supersessions.

**Additional files traced to assess dependencies and wiring (not assumed from `lib.rs`
alone):**

- `crates/qbind-node/src/lib.rs` — module declaration and feature/export surface of
  `safety_record_store` and the `test-utils` gating of fault-injection helpers.
- `crates/qbind-node/Cargo.toml` — `test-utils` feature, and the `required-features =
  ["test-utils"]` declaration on the `run_422_d7d14_safety_record_store_tests` target that
  keeps it out of a default build.
- CodeQL assurance evidence under
  `docs/devnet/run_422_d7d14_fixed_candidate_assurance/` (see §7): `results/dispositions.csv`,
  `results/dispositions.json`, `results/findings_summary_workspace.csv`,
  `logs/checksums.txt`, `logs/commands.sh`, the `diagnostics/` queries and outputs, and the
  `README.md` / `04_independent_review.md` evidence narrative.

---

## 4. Component trust assumptions (as implemented)

1. **Disabled-by-default, MainNet-refused.** The backend policy defaults to `Disabled`; the
   component is never constructed on any production startup/consensus/signing path, and
   MainNet operation is refused. Isolated-component acceptance is evaluated **separately**
   from later production integration, cryptographic (stage-2) verification, durable
   anti-rollback, activation, and launch.
2. **Evidence is carried unverified.** Supporting QC/TC evidence is admitted and persisted
   but typed `EvidenceStatus::Unverified`; it never satisfies a verified-evidence
   prerequisite. Stage-2 signature verification is out of scope for this component.
3. **One shared serialization domain** governs O1–O5 with expected-revision fencing and
   backend-incarnation binding; test-only raw mutation is gated behind `#[cfg(any(test,
   feature = "test-utils"))]`.
4. **Component-charge accounting model** (not heap-only/process-RSS): one `AggregateAuthority`
   ceiling equal to the profile operational aggregate, with subordinate per-class sub-caps;
   three encoded-buffer roles and the borrowed-span vs owned-buffer distinction preserved.

---

## 5. Safety-boundary assessment (source-derived)

**Ownership & mutation.** The owner mutation surface is exactly `attach`, `initialize`
(O1), `open` (O2), `read_validate` (O3), `publish_locked` (O4), and `reacknowledge` (O5);
none prunes, deletes, repairs, migrates, or compacts a generation. `ValidatedRecord` is
opaque and non-`Clone` (uses `try_clone`/`try_duplicate` so every live handle carries its
own charge). Raw mutation (`debug_overwrite_record_for_test` →
`debug_overwrite_record`/`debug_put_raw`, `set_inject`) is compiled only under `test`/
`test-utils`. Recovery-latch transitions are driven only by O3 minting a recovery capability
stamped with the backend incarnation, and O5/O1 clearing it. **No confirmed defect.**

**Recovery lifecycle.** O2 open does **not** make recovered state effective; dependent O4 is
blocked while `recovery_required` holds, until O5 completes (or O1 re-initializes). Uncertain
/ failed / stale O5 outcomes leave the recovery latch engaged (fail-closed). O5 performs a
byte-for-byte complete-content comparison plus an origin-context digest check and a
backend-incarnation check (no cross-store / reopen transfer of acknowledgement). **No
confirmed defect.**

**Established-state checks.** Metadata/record correspondence, revision fences, pinned
context, and semantic (not merely recomputed-hash) association are enforced in `validate.rs`
(P1–P4, TA1–TA8) and `owner.rs`. An expected-revision fence guards O4; the revision
increment is a checked add. **No confirmed defect.**

**Validated ownership & codec.** `codec.rs` decodes through a bounded reader: cross-variant
size gate → minimum length → CRC32 → version → every length/count checked against pinned
context bounds **before** any `Vec::with_capacity` → strict trailing-byte rejection. Unknown
discriminants are refused, not coerced. Empty-signer certificates are structurally refused.
Decoded↔encoded correspondence is re-checked by re-encoding. Original encoded bytes are
retained for O5's complete-content comparison. **No confirmed defect.**

**QC/TC semantics.** `validate.rs` distinguishes accepted view/round, enforces high-QC
correspondence, strict max-high-QC selection via a **borrowed** `select_max_high_qc_ref`
(no clone), membership/uniqueness via a bounded sorted `UNIQ_SET` (no hashing), and quorum
via voting-power `ceil(2W/3)` in `u128`. Evidence remains `Unverified`. P2 binds
`height == lock_view`; the optional `require_height_equals_round` profile choice is kept
separate (H30). **No confirmed defect.**

**Structural admission / checked arithmetic.** `profile.rs` sizing helpers (`add`/`mul`)
use `checked_add`/`checked_mul` and refuse with `ArithmeticOverflowSite::SizeSum`/
`SizeProduct`; `accounting.rs` uses checked `u128` throughout. Bounds are validated before
dependent allocations/copies, including maximum and smallest-over-bound cases, with write/
read closure. **No confirmed defect.**

**Operational accounting.** `accounting.rs` reserves the aggregate authority first, then the
partition, rolling back the aggregate if the partition fails (no disturbance on refusal);
`Reservation` is RAII and releases both on drop; `try_duplicate` prevents uncharged clones;
`AggregateAuthority.bind` is idempotent and refuses a divergent cap. The single combined
ceiling equals `max_aggregate_retained_bytes` (the profile operational aggregate), **not**
the operational+context sum. Per-vector `admit_evidence_capnorm` (CAPNORM_SLACK = 0) runs
**before** the aggregate `admit_evidence_capacity`. The O2 decoded working set is measured by
the borrowed, non-cloning `decoded_working_set_charge(&DecodedRecord)` (not by a cloning
`RetainedGeneration::from_locked`). The three encoded-buffer roles and the borrowed-span vs
owned-buffer distinction are preserved. **No confirmed defect.**

**Namespace & failure handling.** `SafetyStoreError` is a bounded, closed set with
exhaustive `Display` arms (no fail-open default). Backend errors are mapped to typed
variants; unknown/partial state is refused; operation fails closed; there is no production
wiring. **No confirmed defect.**

---

## 6. Newly executed verification (this review) vs inherited evidence

**Newly executed in this review session** (fresh build from the frozen source + run):

```
cargo test -p qbind-node --features test-utils \
  --test run_422_d7d14_safety_record_store_tests -- --test-threads=4 \
  agg_ceiling_is_profile_operational_not_sum o5 h26 h7 h30
```

Result: **26 passed; 0 failed; 0 ignored** (132 filtered out), after a clean `Finished
test profile … in 5m 06s` build. Newly executed tests include: `h7_declared_count_over_bound_refused`,
`h26_*` (adversarial record-level, serialized-cap, both-variant, nested, timeout-entry),
`h30_height_vs_round_distinction` / `d7d14_h30_round_only_correspondence_refused`,
`agg_ceiling_is_profile_operational_not_sum`, the O5 family
(`d7d14_s2_o5_*` measurement-failure fail-closed, `d7d14_m2_o5_actual_simultaneous_object_charge_at_publication`,
`d7d14_o5_publication_envelope_coexistence_reserved_within_aggregate`,
`d7d14_r4_o5_reacknowledge_max_complete_tc_publication_boundary_coverage`,
`h19_o5_refuses_divergence_outside_binding_digest`, `h20_stale_o5_does_not_overwrite_newer`),
the H8b restart-recovery test, H12 competing-handles test, and the child-process
process-death tests (`pd_*`).

**Inherited (not re-executed, attributed to their producing pass):** the previously
reported full integration result (**157 passed / 1 ignored**) and the 3-passed H7 unit
result. These are **not** promoted to newly executed results.

**Child-process tests.** The `pd_*` tests coordinate across a child process boundary and
assert expected termination (including a SIGABRT path whose non-Unix branch at test line
5324 is an `assert!(!status.success())`), surviving on-backend state, and subsequent O5/O4
admission behavior. The review keeps **process death distinct from power loss**: these tests
exercise process-level termination, not device-level durability under power loss.

---

## 7. H-row acceptance assessment (23 accepted rows)

Legend per row: **Obligation** (contract) · **Source** (implementation reasoning) ·
**Tests** (assertions present) · **Exec** (newly executed here / inherited) · **Gap** (any
precise uncovered obligation). Accepted subset only: H2–H12, H16, H18–H25, H26, H27, H30.
Excluded rows H1, H13–H15, H17, H25e, H26l, H28, H29 are **not** imported into this gate.

| H | Obligation (summary) | Source basis | Tests present | Exec | Uncovered obligation |
| --- | --- | --- | --- | --- | --- |
| H2 | First `initialize` on genuine absence → ADMIT O1, no signing | `owner.rs` O1 requires `first_use_intent`, bounded namespace scan, no signer call | lifecycle/`pd_reopen_after_clean_exit_*`, `corr_*` | inherited | none within scope |
| H3 | `open` on missing-but-expected → REFUSE (no auto-init) | `owner.rs` O2 refuses absent-but-expected; no auto-init path exists | open-path refuse tests | inherited | none |
| H4 | Duplicate `initialize` / uncertain-init survival → REFUSE 2nd; O2 opens survivor | `owner.rs` O1 refuses established/partial/malformed | `corr_*`, duplicate-init tests | inherited | none |
| H5 | Valid lock/evidence/context association → ADMIT read/validate | `validate.rs` P1–P4/TA1–TA8 admit valid association | read/validate admit tests | inherited | none |
| H6 | Invalid association / empty-signer QC → structural REFUSE; present-unverified carried | `codec.rs` empty-signer refuse; `validate.rs` stage-3 mismatch refuse; `Unverified` carry | association/empty-signer refuse tests | inherited | none |
| H7 | Size limits / checked arithmetic / bad version / corruption → REFUSE at decode | `codec.rs` bounded decode; `profile.rs` checked `add`/`mul`; §13.8A [H7-EM1] | `h7_declared_count_over_bound_refused` | **newly executed** | range-proof is source-derived (see §13.8A), not decoder-path overflow execution — accurately labeled |
| H8 | Atomic publication; torn/partial → REFUSE; complete successor → O5 re-ack | `backend.rs` WriteBatch+`set_sync(true)`; `owner.rs` frontier gate | `d7d14_h8b_uncertain_successor_restart_then_o5_recovers` | **newly executed** | power-loss durability out of scope (process-death only) |
| H9 | Crash before ack / in-memory install → decide from observable record | `owner.rs` O2/O3 decide from backend record state | crash-before-ack tests | inherited | power-loss out of scope |
| H10 | Successful recovery re-ack → ADMIT; transition effective | `owner.rs` O5 clears latch on complete match | `pd_uncertain_o5_does_not_release_recovery_then_clean_o5_recovers` | **newly executed** | none |
| H11 | Failed recovery re-ack → REFUSE (fail-closed) | `owner.rs` O5 keeps latch on mismatch/failure | `pd_failed_o5_does_not_release_recovery` | **newly executed** | none |
| H12 | Competing handles / stale publication → REFUSE stale O4/O5 | `owner.rs` revision fence + backend incarnation | `h12_competing_handles_stale_o4_o5_leave_newer_bytes_unchanged` | **newly executed** | none |
| H16 | Capacity / atomic replacement / disabled pruning | §13.8A [H16-EM1]: mutation surface has no prune/delete/compact; raw mutation `cfg`-gated | capacity + replacement tests | inherited | structural argument, not executed prune refusal (accurately labeled; no prune API invented) |
| H18 | Explicitly unsupported arrangement → REFUSE | `validate.rs`/`codec.rs` refuse unsupported profile arrangements | unsupported-arrangement refuse tests | inherited | none |
| H19 | Complete identity change outside binding → O5 REFUSE (complete-content) | `owner.rs` O5 byte-for-byte compare beyond CRC/binding | `h19_o5_refuses_divergence_outside_binding_digest`, `h19_pd_fresh_o3_then_o5_refuses_divergent_surviving_content` | **newly executed** | none |
| H20 | Stale O5 vs newer publication → REFUSE (no older-over-newer) | `owner.rs` O5 stale-revision fence between compare and re-publish | `h20_stale_o5_does_not_overwrite_newer` | **newly executed** | none |
| H21 | Cert/lock mismatch despite valid CRC + digest → REFUSE | `validate.rs` requires semantic association, not recomputed hash | cert/lock-mismatch refuse tests | inherited | none |
| H22 | Verified vs unverified → carry unverified; never satisfy verified prereq | `record.rs` `EvidenceStatus` has only `Unverified` (type-level) | unverified-carry tests | inherited | **storage-only**: consumer (stage-2) boundary is out of scope — distinct from H25e |
| H23 | Committed-state comparison failure → REFUSE; legitimate progress allowed | `validate.rs`/`owner.rs` comparison-establishment gate | committed-comparison tests | inherited | none |
| H24 | `Locked`-no-commit lock recovery → ADMIT (P3 skipped); mismatched anchor → REFUSE | `validate.rs` P3 skip for no-commit; anchor-presence consistency check | no-commit lock-recovery tests | inherited | none |
| H25 | Storage-level bootstrap → first `Locked` → ADMIT (monotonic over no-lock) | `owner.rs` O4 publishes first `Locked` over no-lock baseline; stage 1/3 gate | bootstrap→first-Locked tests | inherited | engine bootstrap (H25e) excluded — kept separate |
| H26 | Record-size cap → REFUSE before any app-owned allocation/copy | `codec.rs`/`accounting.rs` bounds before `with_capacity`; `profile.rs` cap | `h26_*` (adversarial, serialized-cap, both-variant, nested, timeout-entry) | **newly executed** | none; retained-L0 lifecycle (H26l) excluded |
| H27 | TC-derived lock logical-only `high_qc` → persist+enforce, carry unverified | `validate.rs` TC high-QC restriction; `Unverified`; no fabricated signer | `d7d14_h27_persisted_tc_restriction_enforced_after_o5_barrier` | **newly executed** | stage-2 verification out of scope |
| H30 | QC `height`/`round` disagreement → bind `height==lock_view`, reject round-only | `validate.rs` P2 height binding; optional `require_height_equals_round` separate | `h30_height_vs_round_distinction`, `d7d14_h30_round_only_correspondence_refused` | **newly executed** | none |

**Assessment of the acceptance evidence as claims.** For the rows exercised by the
allocation/charge tests, the measurements and reservations observed correspond to the
executing operation and its relevant lifetime (e.g.
`d7d14_m2_o5_actual_simultaneous_object_charge_at_publication`,
`d7d14_o5_publication_envelope_coexistence_reserved_within_aggregate`, and the
`agg_ceiling_is_profile_operational_not_sum` test that asserts op-cap + ctx-cap **>**
aggregate-cap). The S2 O5 tests discriminate the **claimed** measurement failure and
fail-closed, rather than merely restating a reservation formula. The adopted H7/H16 methods
are respected; the H7 range proof and H16 structural-unavailability argument are
**source-derived** and labeled as such (not executed decoder-path overflow and not an
executed prune refusal). H22/H25e consumer-boundary and H26/H26l lifecycle distinctions are
preserved.

---

## 8. CodeQL disposition assessment (preserved evidence)

**Reviewed preserved evidence:** `results/dispositions.csv` (52 component-scoped result
rows), `results/dispositions.json`, `results/findings_summary_workspace.csv`,
`logs/checksums.txt`, `logs/commands.sh`, `logs/codeql_version.txt`,
`logs/suite_resolved_queries.txt`, and the `diagnostics/` queries/outputs.

**Concurrence.** All 52 component dispositions are rule `rust/cleartext-logging` at reported
level `warning`, `security-severity 7.5`. The two production-source rows concern a
capacity/bound integer inside a `debug_assert!` at `codec.rs:415`; the remaining rows are
test-file diagnostics. Independently assessing the source/sink rationale: the "sensitive"
values flowing to the log/format sinks are **public consensus-protocol quantities**
(validator indices, views/rounds, revisions, byte capacities) — **not** secrets,
credentials, or keys. I therefore **concur** with the `FALSE_POSITIVE_NON_SENSITIVE` /
`FALSE_POSITIVE_NON_SENSITIVE_TEST_DIAGNOSTIC` dispositions as a **per-location** judgment,
while preserving the rule's reported `warning` / `security-severity 7.5` metadata as a
separate fact (the disposition does not restate or lower that metadata).

**Analyzer limitations preserved (not treated as runtime defects):** the per-file extractor
diagnostic cap on the D7-D14 test file (suppressed contents not recoverable — not described
as benign), the unresolved `$crate::panic::panic_2021` macro expansion at test line 5324 (an
analyzer macro-expansion limitation, **not** a Rust test failure), supplementary-query
provenance limits, and the example-only "Ill-formed type mention" `type_name` tuple results
in two standalone `examples/` helpers (not the component, test, or callers). These are
analyzer limitations; they do not demonstrate runtime defects and do not establish that all
affected analysis is complete.

**Material evidence-preservation gap (see §10).** The A/B SARIF binaries that these
dispositions summarize are **absent at HEAD** (deleted since the evidence revision), so the
SARIF *contents* could not be independently re-verified in this review; the disposition
tables, checksums text, and diagnostic outputs were reviewed instead.

---

## 9. Authorized review writes (this review)

- `docs/devnet/run_422_d7d14_fixed_candidate_assurance/independent_review/00_review_report.md`
  (this file).
- `docs/devnet/run_422_d7d14_fixed_candidate_assurance/04_independent_review.md` — updated
  from the OPEN placeholder to reflect this completed review.
- One concise review-summary entry appended to
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md`.
- One concise entry appended to `docs/whitepaper/contradiction.md`.
- One stale README sentence corrected in
  `docs/devnet/run_422_d7d14_fixed_candidate_assurance/README.md` (Config B "equivalent
  configuration" phrasing; separate execution identity and the existing withdrawal of
  semantic-model equivalence preserved).

No implementation, test, Cargo, lockfile, configuration, CI, or protocol-contract file was
changed.

---

## 10. Findings, evidence gaps, analyzer limitations, and out-of-scope requirements

**A. Confirmed component defects:** **NONE** within the reviewed scope. The component's
ownership, recovery-lifecycle, validation, codec, accounting, and failure-handling logic are
defensively sound against the §13 obligations for the accepted 23-row subset. No
source-derived counterexample was found; no previously closed finding was re-opened with
current-candidate evidence.

**B. Evidence gaps (material):**

1. **A/B SARIF absent at HEAD.** `sarif/A_production_default.sarif.gz` and
   `sarif/B_acceptance_testutils.sarif.gz` (and `diagnostics/FINDINGS.md`) are **deleted**
   at the working-tree HEAD relative to the evidence revision `ecf4cf…`. `logs/checksums.txt`
   still references the SARIF, so those references are **dangling** at HEAD. Consequently the
   task-step-9 instruction to "verify against **unchanged** A/B SARIF" **cannot be
   satisfied** for the SARIF binaries themselves; only the derived dispositions/summary and
   checksum text remain. Restoring the SARIF is **not** in this review's authorized-writes
   set, so the gap is **documented, not remediated**. The README/devnet "durable artifact
   integrity VERIFIED / byte-identical" claims therefore **cannot be independently
   reconfirmed at HEAD** and should be read with this caveat.

**C. Analyzer limitations (not runtime defects):** per-file diagnostic cap; unresolved
`panic_2021` macro; supplementary-query provenance; example-only `type_name` tuple results.
See §8.

**D. Out-of-scope requirements (kept separate, NOT findings against this component):**
production engine/decision wiring, recovery-time (stage-2) signature verification, durable
anti-rollback anchor, activation/launch, and release-binary configured-authority evidence.
These correspond to the §13.9-excluded rows (H1, H13–H15, H17, H25e, H26l, H28, H29) and are
**not** imported into the isolated-component acceptance gate.

**E. Stronger-independence requirement (unmet by this review).** If the isolated-component
acceptance gate requires human / external / organizationally-independent assurance, that
requirement is **explicitly not discharged** by this AI-assisted internal review.

---

## 11. Preserved global verdicts (unchanged by this review)

```
D7D14_STORAGE_COMPONENT=PARTIAL-IMPLEMENTATION
D7D14_STORAGE_ACCEPTANCE=INCOMPLETE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

C4/C5 remain OPEN. Default-disabled / MainNet-refused operation, unverified recovered
evidence, and fail-closed `CurrentEpochUnavailable` are preserved.

---

## 12. Status and acceptance recommendation

- **Review execution:** **COMPLETE** over the defined isolated-component scope (all 9 source
  files + the acceptance target + the operative §13 contract read in full; CodeQL dispositions
  assessed; 26 focused acceptance tests newly executed). One portion is **PARTIAL by
  evidence availability**: the A/B SARIF binaries are absent at HEAD and could not be
  content-verified (§10.B.1).
- **Review outcome:** **No confirmed defects within scope.** One material evidence gap (absent
  A/B SARIF) and the standing stronger-independence limitation are recorded. No finding is
  marked resolved without evidence; inherited results are not promoted to newly executed.
- **Independence limitations:** AI-assisted internal review; **not** a human audit or an
  organizationally-independent security assessment.
- **Does this review support a subsequent isolated-component acceptance decision?**
  **Qualified yes for the storage-only logic**: this review supports an isolated-component
  acceptance decision for the accepted 23-row subset **on the source and executed evidence**,
  **provided** that (a) the absent A/B SARIF evidence gap is closed (artifacts restored and
  re-verified) and (b) any governing requirement for human/organizationally-independent
  assurance is satisfied separately. It does **not** support — and must not be read as
  supporting — production integration, stage-2 cryptographic verification, durable
  anti-rollback, activation, or launch; those remain separate, later gates.
