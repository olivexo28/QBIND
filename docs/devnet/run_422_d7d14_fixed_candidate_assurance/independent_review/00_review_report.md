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
  review**, performed in a review session separate from the implementation session. It is
  **not** an external human audit and **not** an organizationally independent security
  assessment. No contract clause in the operative §13 contract or in the evidence package was
  found that *mandates* human or organizationally-independent assurance for this
  isolated-component gate; this report therefore does **not** invent such an obligation.
  Instead it records the **difference in assurance level** (AI-assisted internal vs.
  human/third-party) as a stated **limitation** on the strength of the assurance this review
  provides. If a governing requirement elsewhere does impose a stronger-independence
  obligation, that requirement's actual source would have to be quoted; none is quoted here
  because none was located. This review assesses implementation reports and CodeQL
  dispositions as claims; it does not merely restate them.

---

## 2. Evidence baseline and source correspondence (independently established)

| Item | Value |
| --- | --- |
| Actual working branch | `copilot/run-422-restore-evidence-package` (used as supplied; **not** switched or renamed) |
| Starting HEAD (this continuation) | `afc0fa1fd8add76e7c75cd7a13b20c06897db8ee` |
| Evidence-restoration commit | `f8d1df0195bb06457db5613d8769006664388f61` (byte-exact restore of 33 artifacts from `ecf4cf…`) |
| Final HEAD | the review-completion commit pushed on this branch through the supplied workflow (this document's commit) |
| Upstream | `origin/copilot/run-422-restore-evidence-package` |
| Worktree status (start / end) | clean / clean (only documentation under `docs/` changed; zero non-doc drift from the frozen candidate) |
| Frozen implementation/test candidate | `aad0a4aaca8f66580d257c3468f1c27059145dbd` |
| Candidate tree | `82caed801176b243beda89ad07e5a7376fe958e9` |
| Reviewed evidence revision | `ecf4cfdcc36e9438293173d89e44cd819d709ca5` |
| Prior reviewed report revision | `71e205264b69b8949e2fc6a2dfc58ba7de71bc85` |

**HEAD-attribution correction.** An earlier draft of this report recorded the working branch as
`copilot/copilotcopilotrun-422-d7-d14-please-work-again` and a single starting/final HEAD of
`53a2f7c…`. That attribution is **corrected here**: this continuation ran on branch
`copilot/run-422-restore-evidence-package` with starting HEAD `afc0fa1…` (whose first parent is
`53a2f7c…`). The starting and final HEAD are **not** identical in this continuation, because this
session added documentation commits (the evidence restoration `f8d1df0…` and this report
completion).

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

**Evidence restoration (this continuation).** The supplied review baseline had three evidence
files **absent** (`sarif/A_production_default.sarif.gz`, `sarif/B_acceptance_testutils.sarif.gz`,
`diagnostics/FINDINGS.md`) and **sixteen** present checksum-listed artifacts whose bytes had
drifted through CRLF conversion and/or final-newline removal (so they failed their recorded
SHA-256 hashes), plus additional non-checksum-listed raw `logs/` artifacts with the same
formatting drift. All affected artifacts remained retrievable at `ecf4cf…`. In this continuation
**33 files** were restored by writing the exact `ecf4cf…` git blob bytes (no checkout/filter/editor
normalization) and verifying `git hash-object` equals the `ecf4cf…` blob id for each. After
restoration, the only files under the assurance directory that differ from `ecf4cf…` are the three
review-managed documents (`independent_review/00_review_report.md`, `04_independent_review.md`,
`README.md`); `manifests/` were already byte-identical. Recorded checksums were **not** rewritten to
accommodate the drift — the **original bytes** were restored. Verification results are in §8/§10.

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
  `README.md` / `04_independent_review.md` evidence narrative. **The restored full A/B SARIF
  reports** `sarif/A_production_default.sarif.gz` and `sarif/B_acceptance_testutils.sarif.gz`
  and `diagnostics/FINDINGS.md` were read directly this continuation (see §8).

**External dependency trace (concrete files/functions actually used by the component).** The
component is not self-contained; the following cross-crate/cross-module dependencies were
inspected directly rather than assumed:

- **CRC framing helper.** `crate::storage::signing_journal_crc32` (imported at `codec.rs:21`
  and `backend.rs:19`). In `codec.rs` it is applied as a 4-byte big-endian CRC32 **trailer over
  all preceding bytes** on encode (`encode …`, `codec.rs:743-744`) and re-checked before any
  application-owned allocation on decode (`codec.rs:802-807`, refusing with
  `StructuralRefusalDetail::Static("CRC32 mismatch")`). The fixed framing prefix is modelled in
  accounting as `CRC_PREFIX = 4` (`accounting.rs:318`), added into both staging-envelope size
  budgets (`accounting.rs:336-337`). CRC is a **framing/integrity** check only — it is explicitly
  **not** treated as a semantic or cryptographic association (§5 "QC/TC semantics").
- **QC / TC representations and encoding dependencies.** The retained evidence types are
  **external consensus types**, re-exported/aliased in `record.rs`:
  `qbind_consensus::timeout::TimeoutCertificate<[u8; 32]>` (aliased `TimeoutCert`, `record.rs:17`),
  `qbind_consensus::qc::QuorumCertificate` (`validate.rs:18`), `qbind_consensus::timeout::TimeoutMsg`
  (`validate.rs:19`), `WireQc` / `TimeoutMessage` (`codec.rs:19`), and `qbind_consensus::ids::ValidatorId`
  (used across `record.rs`, `profile.rs`, `validate.rs`, `codec.rs`). The component's own
  `SupportingEvidence` enum carries `TcDerived { high_qc: LogicalQc, tc: TimeoutCert }` /
  `QcLocked` variants (`record.rs:42-57`). Encoding/decoding of the TC is the component's own
  bounded codec — `encode_timeout_cert` (`codec.rs:287`), `decode_timeout_cert` (`codec.rs:321`),
  `admit_timeout_cert` (`codec.rs:624`) — with the `high_qc` presence discriminant strictly
  gated to `0`/`1` (`error.rs:746`). The component **retains the serialized `TimeoutCertificate`**
  and a logical `high_qc`, and never re-verifies the external certificate's signatures (evidence
  stays `EvidenceStatus::Unverified`).
- **RocksDB API behaviour relied upon.** `backend.rs` uses `rocksdb::DB` (`:409`), `rocksdb::Options`
  + `DB::open` (`:492-494`), and durable atomic publication via `rocksdb::WriteBatch`
  (`publish_atomic`, `:824`) committed with `rocksdb::WriteOptions::set_sync(true)`
  (`:894-895`, and the two other synced write paths `:1007-1008`, `:1020-1021`). The relied-upon
  behaviour is: a single `WriteBatch` applied under `set_sync(true)` is an **all-or-nothing
  synchronous commit** of both the record and meta column entries, and reads are
  length-/checksum-bounded (`read_checksummed`, `:705`; `read_record`/`read_meta`, `:630/:637`).
  The review notes (as a stated assumption, below) that this provides **process-level** atomicity
  and fsync-ordered durability as documented by RocksDB; it does **not**, by itself, establish
  device-level power-loss durability or DB-wide anti-rollback — consistent with the
  power-loss/anti-rollback exclusions kept in §10.D.

**Remaining dependency assumptions (not independently re-verified here).** (1) The internal
cryptographic correctness of `qbind_consensus` QC/TC verification is **out of scope** (the
component carries evidence `Unverified`); only the component's structural encode/decode/admit of
these types was inspected. (2) RocksDB's `set_sync(true)` durability semantics are relied upon as
documented; the underlying `librocksdb-sys` implementation and filesystem/device guarantees were
**not** audited. (3) `signing_journal_crc32`'s polynomial/implementation in `crate::storage` was
used as the integrity primitive and not re-derived. A full audit of these third-party/internal
modules is not required for this isolated-component gate and is explicitly not claimed.

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

**Executed during the source-review phase (earlier session of this review)** (fresh build from
the frozen source + run):

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

**Newly executed in this continuation (evidence restoration + SARIF completion phase).** No
`cargo` tests were re-run in this continuation, and **no citation added below re-executes any
test** — the 26-test run above remains attributed to its earlier command and selected tests.
The checks newly executed here are evidence-integrity and SARIF-content verifications:

- **Git blob-identity restoration** of 33 artifacts: for each restored file, `git hash-object`
  on the written bytes equals `git rev-parse ecf4cf…:<path>` (0 mismatches).
- **Recorded-checksum verification** after restoration: all committed checksum-listed artifacts
  (compressed SARIF A/B, `results/*`, `diagnostics/*`) match their `logs/checksums.txt` SHA-256.
- **SARIF decompression + uncompressed digest**: `gzip -dc` of A and B produced valid SARIF whose
  uncompressed SHA-256 equal the recorded `…(uncompressed)` values
  (`5726612057bc…` for A, `c17c54ca618c…` for B).
- **JSON validity + workspace counts**: both SARIF parse as valid JSON; A carries **50** workspace
  results and B carries **828** (matching `results/component_scoped_findings.json`
  `total_workspace_results = 828`).
- **SARIF component-scoped enumeration**: A has **2** and B has **50** component-scoped results
  (50 of A's and 828 of B's are workspace-wide), all rule `rust/cleartext-logging`; see §8.

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
| H2 | First `initialize` on genuine absence → ADMIT O1, no signing | `owner.rs` O1 requires `first_use_intent`, bounded namespace scan, no signer call | `d7d14_fa_o1_real_initialize_peak_reserves_borrowed_decoded_local` (real O1 admit path), `o1_refuses_duplicate_initialization_and_missing_intent` (intent required; no signer call), `pd_reopen_after_clean_exit_requires_o5_before_o4` | inherited | none within scope |
| H3 | `open` on missing-but-expected → REFUSE (no auto-init) | `owner.rs` O2 refuses absent-but-expected; no auto-init path exists | `corr_missing_committed_history_for_anchored_refused`, `corr_unknown_namespace_key_refuses_o1_without_repair` | inherited | none |
| H4 | Duplicate `initialize` / uncertain-init survival → REFUSE 2nd; O2 opens survivor | `owner.rs` O1 refuses established/partial/malformed | `o1_refuses_duplicate_initialization_and_missing_intent`, `pd_duplicate_o1_after_surviving_init_refused` (second O1 refused across surviving init) | inherited | none |
| H5 | Valid lock/evidence/context association → ADMIT read/validate | `validate.rs` P1–P4/TA1–TA8 admit valid association | read/validate admit tests | inherited | none |
| H6 | Invalid association / empty-signer QC → structural REFUSE; present-unverified carried | `codec.rs` empty-signer refuse; `validate.rs` stage-3 mismatch refuse; `Unverified` carry | association/empty-signer refuse tests | inherited | none |
| H7 | Size limits / checked arithmetic / bad version / corruption → REFUSE at decode | `codec.rs` bounded decode; `profile.rs` checked `add`/`mul`; §13.8A [H7-EM1] | `h7_declared_count_over_bound_refused` | **newly executed** | range-proof is source-derived (see §13.8A), not decoder-path overflow execution — accurately labeled |
| H8 | Atomic publication; planted-malformed surviving state → REFUSE; complete successor → O5 re-ack | `backend.rs` WriteBatch+`set_sync(true)`; `owner.rs` frontier gate | `d7d14_h8a_planted_malformed_successor_across_process_death_refused` (refusal of a **test-planted malformed** surviving fixture across process termination — **not** naturally occurring torn-write/power-loss evidence), kept separate from `d7d14_h8b_uncertain_successor_restart_then_o5_recovers` (complete-successor restart recovery) | **newly executed** | power-loss/torn-write durability out of scope (process-death + test-planted fixtures only) |
| H9 | Crash before ack / in-memory install → decide from observable record | `owner.rs` O2/O3 decide from backend record state | crash-before-ack tests | inherited | power-loss out of scope |
| H10 | Successful recovery re-ack → ADMIT; transition effective | `owner.rs` O5 clears latch on complete match | `pd_uncertain_o5_does_not_release_recovery_then_clean_o5_recovers` | **newly executed** | none |
| H11 | Failed recovery re-ack → REFUSE (fail-closed) | `owner.rs` O5 keeps latch on mismatch/failure | `pd_failed_o5_does_not_release_recovery` | **newly executed** | none |
| H12 | Competing handles / stale publication → REFUSE stale O4/O5 | `owner.rs` revision fence + backend incarnation | `h12_competing_handles_stale_o4_o5_leave_newer_bytes_unchanged` | **newly executed** | none |
| H16 | Capacity / atomic replacement / disabled pruning | §13.8A [H16-EM1]: mutation surface has no prune/delete/compact; raw mutation `cfg`-gated | capacity + replacement tests | inherited | structural argument, not executed prune refusal (accurately labeled; no prune API invented) |
| H18 | Co-located record+evidence single store; split-store interface structurally unavailable | `record.rs`/`owner.rs` keep record and evidence in one store; no split-store/partial-cross-store API exists | `h18_record_and_evidence_co_located_single_store_no_partial_cross_store` — demonstrates **co-location and structural unavailability** of a split-store interface (**not** an executed refusal through a split-store API that does not exist) | inherited | none — structural unavailability, not an invented split-store refusal path |
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

## 8. CodeQL disposition assessment (full A/B SARIF inspected)

**Evidence now read directly (restored, byte-verified).** The previously-omitted step is
completed here: the full A/B SARIF reports were decompressed and inspected directly —
`sarif/A_production_default.sarif.gz` and `sarif/B_acceptance_testutils.sarif.gz` (restored to
their `ecf4cf…` bytes; compressed and uncompressed SHA-256 both match the recorded checksums) —
together with `diagnostics/FINDINGS.md`, `results/dispositions.csv` (52 rows),
`results/dispositions.json`, `results/component_scoped_findings.json`,
`results/findings_summary_workspace.csv`, `logs/checksums.txt`, `logs/commands.sh`,
`logs/codeql_version.txt`, `logs/suite_resolved_queries.txt`, and the `diagnostics/` queries.

**SARIF structure independently observed.** Both runs are CodeQL `2.27.2` (organization GitHub),
one run each, 30 rules, one invocation each (`executionSuccessful = true`). Workspace-wide result
totals are **A = 50** and **B = 828** (B’s 828 matches
`component_scoped_findings.json.total_workspace_results`). Workspace results by rule:
A = {`rust/hard-coded-cryptographic-value` 28, `rust/cleartext-logging` 20, `rust/unused-variable` 2};
B = {`rust/hard-coded-cryptographic-value` 671, `rust/cleartext-logging` 147, `rust/log-injection` 8,
`rust/unused-variable` 2}. The rule metadata for `rust/cleartext-logging` is, in both SARIF files,
`defaultConfiguration.level = warning`, `properties.security-severity = 7.5`,
`problem.severity = warning`, tags `security, external/cwe/cwe-312, cwe-359, cwe-532`.

**Component-scoping independently reproduced.** Restricting each run to results whose location is
in `src/safety_record_store/*` or the D7-D14 acceptance test yields exactly **2** results in A and
**50** in B (= the **52** dispositioned rows; B’s 50 equals `component_results` in
`component_scoped_findings.json`). **Every one** of the 52 component-scoped results is rule
`rust/cleartext-logging`; the hard-coded-cryptographic-value / unused-variable / log-injection
workspace results fall **outside** the component and are correctly **not** dispositioned here.

**Source/sink traces verified against the SARIF codeFlows.** All 52 component results carry
codeFlows. In both configurations **every** codeFlow **source** resolves into
`src/safety_record_store/codec.rs` (the bounded decode path — `decode_timeout_cert` and the
capacity/bound helpers). Only **one** production-located **sink** exists per configuration: the
`debug_assert!` at `codec.rs:415` (`"evidence cert backing capacity {} diverged from the admitted
cap {cert_cap}"`, value = integer capacity bound, compiled out of release builds). All remaining
sinks are test-assertion/format diagnostics in the D7-D14 integration test (e.g. the A sink at
`tests/…:8625`). Thus the two "production-source" dispositions concern `codec.rs:415`/`codec.rs:546`
public integer quantities, and the 50 test-diagnostic dispositions concern synthetic fixture /
error-Debug / public-capacity values — exactly as the disposition CSV records.

**Concurrence (per-location) with all 52 dispositions.** Independently assessing each source→sink
rationale, the values reaching the logging/format sinks are **public consensus-protocol
quantities** (validator indices, views/rounds, revisions, byte-capacity bounds) and synthetic test
fixtures — **not** secrets, credentials, or keys. I therefore **concur** with the
`FALSE_POSITIVE_NON_SENSITIVE` (2 rows) and `FALSE_POSITIVE_NON_SENSITIVE_TEST_DIAGNOSTIC` (50 rows)
dispositions, as a **per-location** judgment, with **no disagreements**. Four facts are kept
**separate** and are **not** restated or lowered by the disposition:

1. the rule’s reported **level `warning`**;
2. the rule’s **`security-severity` `7.5`**;
3. the **per-location false-positive** disposition (a judgement about these specific
   source/sink pairs, not a claim about the rule);
4. **analyzer coverage limitations** (below) — which bound how complete the analysis is and are
   not folded into the false-positive judgement.

**Analyzer limitations preserved (not treated as runtime defects, and not “globally lost”).** The
A/B SARIF are **present and inspected** here; the issue was their prior **absence on the branch and
byte drift**, now resolved. The following remain genuine coverage limitations, confirmed against
the restored SARIF invocation data and `diagnostics/FINDINGS.md`: (a) the per-file extractor
**diagnostic cap** (`rust/diagnostics/extraction-warnings`) that caps the D7-D14 test file in
Config B — the SARIF carries no suppressed count or contents, so suppressed items are **not**
recoverable and are **not** asserted benign; (b) the unresolved `$crate::panic::panic_2021` macro
expansion at `tests/…:5324` (one `error`-level notification in B), an analyzer macro-expansion
limitation and **not** a Rust test failure; (c) supplementary diagnostic-query **provenance**
limits (no `qlpack.lock.yml` captured at diagnostic-execution time; the `codeql/rust-all` pin was
added by the finishing pass and does not retro-prove the loaded library version); and (d) the two
example-only **“Ill-formed type mention”** `TupleTypeRepr` results in two standalone `examples/`
release-binary helpers — not the component, the test, or its callers. These limitations do not
demonstrate runtime defects and do not establish that all affected analysis is complete.

---

## 9. Authorized review writes (this review)

- **Exact evidence restoration within the assurance directory** — 33 artifacts (the absent
  `sarif/A_production_default.sarif.gz`, `sarif/B_acceptance_testutils.sarif.gz`,
  `diagnostics/FINDINGS.md`, the 16 drifted checksum-listed artifacts under `results/` and
  `diagnostics/`, and the drifted raw `logs/` artifacts) rewritten to their exact `ecf4cf…`
  git-blob bytes; original recorded checksums preserved (not rewritten).
- `docs/devnet/run_422_d7d14_fixed_candidate_assurance/independent_review/00_review_report.md`
  (this file) — completed (SARIF inspection, dependency trace, H-row references, HEAD
  attribution, independence framing).
- `docs/devnet/run_422_d7d14_fixed_candidate_assurance/04_independent_review.md` — reconciled to
  reflect this completed review.
- One concise completion entry appended to
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md`.
- One concise entry appended to the contradiction ledger `docs/whitepaper/contradiction.md`.
- Affected operative statements reconciled in
  `docs/devnet/run_422_d7d14_fixed_candidate_assurance/README.md` (artifact-integrity/SARIF-present
  phrasing; separate execution identity and the existing withdrawal of semantic-model equivalence
  preserved).

No implementation, test, Cargo, lockfile, configuration, CI, or protocol-contract file was
changed. Verified: **zero non-documentation drift** from the frozen candidate `aad0a4a…` (all
changes are under `docs/`).

---

## 10. Findings, evidence gaps, analyzer limitations, and out-of-scope requirements

**A. Confirmed component defects:** **NONE** within the reviewed scope. The component's
ownership, recovery-lifecycle, validation, codec, accounting, and failure-handling logic are
defensively sound against the §13 obligations for the accepted 23-row subset. No
source-derived counterexample was found; no previously closed finding was re-opened with
current-candidate evidence.

**B. Evidence gaps (resolved in this continuation + residual non-repository input):**

1. **A/B SARIF + FINDINGS.md — restored and verified (gap closed).** On the supplied branch
   `sarif/A_production_default.sarif.gz`, `sarif/B_acceptance_testutils.sarif.gz`, and
   `diagnostics/FINDINGS.md` were **absent**, and sixteen present checksum-listed artifacts had
   **byte-drifted** (CRLF / final-newline), failing their recorded hashes. All of these remained
   retrievable at `ecf4cf…` and have been **restored to their exact original bytes** (git
   blob-identity verified). After restoration: every recorded committed-file checksum **passes**;
   the compressed and **uncompressed** SARIF SHA-256 match the recorded values; both SARIF are
   valid JSON with workspace counts **A = 50 / B = 828**; and the SARIF contents were inspected
   (§8). The earlier "cannot verify / dangling reference" caveat is therefore **retired**: the
   artifacts are present, byte-exact, and content-verified. The README/devnet artifact-integrity
   statements are reconciled accordingly.
2. **Non-repository input not retrieved (reported separately, not reverified).** The original
   downloaded CodeQL tooling bundle `codeql-bundle-linux64.tar.gz` (recorded SHA-256
   `f002864be6dd…` in `logs/checksums.txt`) is **not** part of the repository and was **not**
   retrieved in this review. Its recorded digest is carried forward as a **claim**; this review
   does **not** assert it reverified that bundle. No CodeQL re-execution was performed or required.

**C. Analyzer limitations (not runtime defects):** per-file diagnostic cap; unresolved
`panic_2021` macro; supplementary-query provenance; example-only `type_name` tuple results.
See §8.

**D. Out-of-scope requirements (kept separate, NOT findings against this component):**
production engine/decision wiring, recovery-time (stage-2) signature verification, durable
anti-rollback anchor, activation/launch, and release-binary configured-authority evidence.
These correspond to the §13.9-excluded rows (H1, H13–H15, H17, H25e, H26l, H28, H29) and are
**not** imported into the isolated-component acceptance gate.

**E. Assurance-level limitation (not an established contractual obligation).** This is an
AI-assisted internal review. No clause mandating human / external / organizationally-independent
assurance for this isolated-component gate was located in the operative §13 contract or the
evidence package; none is quoted. The difference between this AI-assisted internal assurance and
a human/third-party audit is recorded here as a **limitation on assurance strength**, **not** as
an established unmet contractual requirement. If such a requirement exists elsewhere, its actual
source must be quoted before it can be treated as binding.

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

- **Review execution completeness:** **COMPLETE** over the defined isolated-component scope. All
  9 source files, the acceptance target, and the operative §13 contract were read in full; the
  previously-omitted **full A/B SARIF inspection and 52-disposition assessment are now done**
  (§8); the external dependency trace (CRC helper, QC/TC types + encoding, RocksDB API) is
  complete (§3); H-row references were made traceable to exact symbols (§7); and the absent/
  drifted evidence was restored byte-exact and verified (§2/§10.B). The earlier "PARTIAL by
  evidence availability" caveat no longer applies — the SARIF are present, byte-exact, and
  content-verified. The only residual non-repository item is the CodeQL tooling bundle, which was
  not retrieved and is reported as an un-reverified external claim, not a repository gap (§10.B.2).
- **Confirmed findings within inspected scope:** **No confirmed findings** (no confirmed component
  defects) against the §13 obligations for the accepted 23-row subset. "No confirmed findings"
  does **not** mean the absence of all possible defects. No previously closed implementation
  finding was re-opened (no current-source counterexample was found); inherited results are not
  promoted to newly executed.
- **Remaining evidence/analysis limitations:** the CodeQL analyzer coverage limitations
  (per-file diagnostic cap with non-recoverable suppressed contents; unresolved `panic_2021`
  macro; supplementary-query provenance; example-only type-mention results) in §8/§10.C; the
  stage-2 / anti-rollback / activation items that are **out of scope** (§10.D); the un-retrieved
  tooling bundle (§10.B.2); and the assurance-level limitation (AI-assisted internal, not a human
  / organizationally-independent audit — recorded as a limitation, not an unmet obligation,
  §1/§10.E).
- **Does this review support an isolated-component acceptance decision?** **Qualified yes for the
  storage-only logic** of the accepted 23-row subset, on the inspected source, the restored and
  verified CodeQL evidence, and the earlier focused-test execution. It does **not** support — and
  must not be read as supporting — production integration, stage-2 cryptographic verification,
  durable anti-rollback, activation, or launch; those remain separate, later gates, and the global
  verdicts in §11 are unchanged.