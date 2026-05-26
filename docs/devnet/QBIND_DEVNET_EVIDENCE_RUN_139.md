# QBIND DevNet Evidence — Run 139

**Subject**: Release-binary closure of the v2 (ratification-v2) SIGHUP
live trust-bundle reload-apply MUTATING binary surface — the Run 138
source/test wiring exercised end-to-end on a real
`target/release/qbind-node` daemon driven by a real `kill -HUP <pid>`
against ephemeral DevNet fixtures.

**Scope notice (mandatory per `task/RUN_139_TASK.txt`)**

* **Run 139 is release-binary evidence only.** No production runtime
  source was changed. No tests were edited. No CLI flag, metric,
  wire-format or on-disk schema changed.
* SIGHUP live-reload v2 release-binary evidence (PQC-aware
  `qbind-node` daemon driven by a real `kill -HUP <pid>` against a
  populated v2 sidecar + data-dir marker + reload candidate)
  is **landed by this run** (see scenario matrix below).
* Snapshot / restore v2 marker wiring **remains open**.
* Live inbound 0x05 v2 PQC trust-bundle frame validation **remains
  open**.
* Peer-driven live trust-bundle apply **remains open**.
* Signing-key rotation / revocation lifecycle **remains open**.
* KMS / HSM authority-key custody **remains open**.
* MainNet governance attestation track **remains open**.
* Full C4 acceptance **remains open**.
* C5 acceptance **remains open**.
* Run 139 does **not** weaken v1 SIGHUP behaviour (Run 074 / Run 121),
  the v1 startup gate (Run 105 / Run 119), the v2 startup gate
  (Run 136), the v2 reload-apply path (Run 134), or any pre-Run-138
  invariants.

## What landed in Run 139

`task/RUN_139_TASK.txt` §§4–7 — implemented in:

* `scripts/devnet/run_139_sighup_v2_live_reload_release_binary.sh`
  * Builds `target/release/qbind-node` and the existing
    `run_133_v2_validation_only_fixture_helper` release example
    (no new fixture helper introduced — Run 133's v2 sidecar
    catalogue covers every Run 139 scenario).
  * Mints ephemeral DevNet fixtures via the helper.
  * For each scenario: dedicated `--data-dir`, dedicated loopback port,
    starts `qbind-node` in the long-running P2P mode (the only mode
    that installs the Run 074 SIGHUP handler) with the appropriate
    `--p2p-trust-bundle <baseline-bundle>`,
    `--p2p-trust-bundle-signing-key`,
    `--p2p-trust-bundle-live-reload-enabled
    --p2p-trust-bundle-live-reload-path <reload-bundle>`, and
    `--p2p-trust-bundle-ratification <sidecar>
    --p2p-trust-bundle-ratification-enforcement-enabled` (the
    no-sidecar regression substitutes
    `--p2p-trust-bundle-allow-unratified-testnet-devnet` instead).
  * Polls the node's stderr for the canonical
    `[binary] Run 074: SIGHUP-driven live trust-bundle reload-apply
    trigger ENABLED. Candidate path: …` log line, captures the PID,
    snapshots the data-dir's `pqc_authority_state.json` and
    `pqc_trust_bundle_sequence.json` bytes + SHA-256 hashes (the
    "pre-SIGHUP" snapshot), optionally rewrites the on-disk sidecar
    and / or reload candidate bundle in place (the mid-flight
    mutation is how the scenario distinguishes "what was loaded at
    startup" from "what the SIGHUP sees"), delivers `kill -HUP
    <PID>`, waits for the canonical
    `[binary] Run 074: VERDICT=applied …` or
    `[binary] Run 138: VERDICT=marker-rejected-v2 …` log line, then
    SIGTERMs the node, waits for a clean exit, and snapshots the
    data-dir again (the "post-SIGHUP" snapshot).
  * Asserts per-scenario invariants (see "Mutating-surface
    invariants" below).
  * Writes a complete evidence archive under
    `docs/devnet/run_139_sighup_v2_live_reload_release_binary/`.

* `docs/devnet/run_139_sighup_v2_live_reload_release_binary/`
  * `summary.txt` — captured metadata (`git_commit`, `rustc`,
    `cargo`, `qbind-node` SHA-256 + ELF Build ID, fixture-helper
    SHA-256 + ELF Build ID, exact CLI command template,
    per-scenario rc / class / PID, and the prose pass-checks per
    invariant category).
  * `logs/scenario_*.stdout.log`, `logs/scenario_*.stderr.log` —
    real captured stdout / stderr from the daemon.
  * `exit_codes/scenario_*.exit_code` — daemon exit code after
    SIGTERM.
  * `marker_hashes/scenario_*.marker_{pre,post}_sighup.sha256` —
    SHA-256 of `pqc_authority_state.json` before and after the
    trigger window. Aggregated as
    `marker_hashes/marker_hashes.csv`.
  * `sequence_hashes/scenario_*.sequence_{pre,post}_sighup.sha256`
    — SHA-256 of `pqc_trust_bundle_sequence.json` before and
    after the trigger window.
  * `signal_timestamps/scenario_*.sighup.timestamp` and
    `signal_timestamps/scenario_*.verdict.timestamp` — UTC
    timestamps of `kill -HUP` delivery and VERDICT observation.
  * `pids/scenario_*.pid` — the captured daemon PID.
  * `data/scenario_*/` — the daemon's `--data-dir` after the
    scenario (including the pre-SIGHUP snapshot copies).
  * `inventories/scenario_*.inventory.txt` — filename-only
    listing of every scenario data-dir (no secret bytes).
  * `fixtures/devnet/` — the ephemeral DevNet fixtures the
    scenarios were driven against.

## Mutating-surface invariants

| Surface                                | Run | Path                  | Status                          |
|----------------------------------------|-----|-----------------------|---------------------------------|
| Startup `--p2p-trust-bundle`           | 119 | v1 marker             | landed                          |
| Startup `--p2p-trust-bundle`           | 136 | v2 marker             | landed (release-binary: Run 137)|
| Reload-apply (in-process)              | 070 | v1 (no marker)        | landed                          |
| Reload-apply (in-process)              | 134 | v2 marker             | landed                          |
| SIGHUP live trust-bundle reload        | 074 | v1 (no marker)        | landed (release-binary: Run 115)|
| SIGHUP live trust-bundle reload        | 121 | v1 marker             | landed (release-binary: Run 122)|
| SIGHUP live trust-bundle reload        | 138 | v2 marker             | landed (source/test: Run 138)   |
| **SIGHUP live trust-bundle reload**    | **139** | **v2 marker** | **landed (release-binary: this run)** |
| Snapshot / restore                     | —   | v2 marker             | open                            |
| Live inbound 0x05 v2                   | —   | v2 marker             | open                            |
| Peer-driven apply                      | —   | —                     | open                            |
| Signing-key rotation / revocation      | —   | —                     | open                            |

## Scenario matrix actually covered on the release binary

All eleven scenarios were driven against a real
`target/release/qbind-node` process with a real `kill -HUP <pid>`.
Every scenario exited with `rc=0` (clean SIGTERM shutdown after the
SIGHUP outcome was observed).

| ID | Scenario file (under `logs/`)                                            | Class       | Outcome |
|----|--------------------------------------------------------------------------|-------------|---------|
| A1 | `scenario_A1_first_accepted_v2_sighup.{stdout,stderr}.log`               | accept-v2   | pass    |
| A2 | `scenario_A2_idempotent_v2_sighup.{stdout,stderr}.log`                   | accept-v2   | pass    |
| A3 | `scenario_A3_higher_sequence_v2_sighup.{stdout,stderr}.log`              | accept-v2   | pass    |
| A4 | `scenario_A4_v1_to_v2_migration.{stdout,stderr}.log`                     | accept-v2   | pass    |
| R1 | `scenario_R1_lower_sequence_v2_refused.{stdout,stderr}.log`              | reject-v2   | pass    |
| R2 | `scenario_R2_same_seq_different_digest_v2_refused.{stdout,stderr}.log`   | reject-v2   | pass    |
| R3 | `scenario_R3_bad_signature_v2_refused.{stdout,stderr}.log`               | reject-v2   | pass    |
| R4 | `scenario_R4_wrong_chain_v2_refused.{stdout,stderr}.log`                 | reject-v2   | pass    |
| R5 | covered by Run 138 source/test orchestration shape (see §"R5" below)     | —           | partial |
| R6 | `scenario_R6_v1_sighup_regression.{stdout,stderr}.log`                   | accept-v1   | pass    |
| R7 | `scenario_R7_no_sidecar_regression.{stdout,stderr}.log`                  | accept-v1   | pass    |
| R8 | `scenario_R8_repeated_sighup_serialization.{stdout,stderr}.log`          | accept-v2   | pass    |

### Per-class invariants the harness asserts in-line

**Accepted v2 scenarios (A1 / A3 / A4 / R8)** — captured in
`assert_v2_accept_invariants` in the harness:

* Strict line-number ordering on the same captured stderr stream:
  `Run 074: SIGHUP received` line **<** `Run 074: VERDICT=applied`
  line.
* The VERDICT line itself contains `sequence_commit=ok` — the in-log
  confirmation that the existing Run 070 `commit_sequence` boundary
  returned `Ok` before the v2 marker post-commit persist ran. (The
  Run 055 `trust-bundle sequence persistence` log line is emitted
  once at startup as `first-load` and is **not** re-emitted per
  SIGHUP — proof of the SIGHUP commit lives in the VERDICT line and
  the on-disk marker bytes. The Run 138 wiring keys the post-commit
  persist exclusively off the `Ok(applied)` return of
  `apply_validated_candidate_with_previous`, so a marker with
  `last_update_source="sighup-reload"` cannot exist without an
  `Ok` commit.)
* `data_dir/pqc_authority_state.json` post-SIGHUP has
  `"record_version": 2`,
  `"latest_authority_domain_sequence": <expected>`, and
  `"last_update_source": "sighup-reload"`.
* No `Run 138: VERDICT=marker-rejected-v2` line emitted by the
  accepted trigger.
* No `Run 138: VERDICT=FATAL-marker-persist-v2` line emitted.
* No `Run 121: VERDICT=FATAL-marker-persist` line emitted.

**Idempotent v2 scenario (A2)** — captured in
`assert_v2_idempotent_invariants`:

* `pqc_authority_state.json` bytes are byte-identical pre / post the
  SIGHUP (the harness `cmp -s` 's the pre-SIGHUP snapshot copy
  against the post-SIGHUP file). See
  `marker_hashes/marker_hashes.csv` — scenario A2 lists the same
  SHA-256 in both `marker_pre_sighup_sha256` and
  `marker_post_sighup_sha256` columns.
* The marker post-SIGHUP still has `"record_version": 2`.
* No `Run 138: VERDICT=marker-rejected-v2` was emitted.

**Rejected v2 scenarios (R1–R4)** — captured in
`assert_v2_reject_invariants`:

* `Run 138: VERDICT=marker-rejected-v2` is emitted with a
  scenario-specific reason substring (`lower than persisted` /
  `same-sequence` / `signature failed` / `ChainMismatch` /
  `MalformedOrUnsupportedMarkerRejected` /
  `LowerV2SequenceRefused` / `SameSequenceConflicting`).
* `marker_pre_sighup_sha256 == marker_post_sighup_sha256` (refusal
  preserves on-disk marker bytes — see
  `marker_hashes/marker_hashes.csv`).
* `sequence_pre_sighup_sha256 == sequence_post_sighup_sha256`
  (refusal preserves the trust-bundle sequence record).
* No `Run 055: trust-bundle sequence persistence` line was emitted
  **between** the SIGHUP-received and VERDICT log lines (the
  harness `sed -n "${sighup_line},${verdict_line}p"`'s a section
  of stderr and asserts the absence of the Run 055 line, the
  `VERDICT=applied` line, any `falling back to --p2p-trusted-root`
  / `trusted-root fallback` line, any `live inbound 0x05` /
  `peer-driven live apply` line, any `snapshot/restore v2` line,
  any `KMS` / `HSM` line, and any
  `signing-key (rotation|revocation) lifecycle` line).
* No `.tmp` marker sibling left behind under the scenario's
  data-dir (the harness `fail`s the entire run otherwise).

**v1 / no-sidecar regressions (R6 / R7)** — captured in
`assert_v1_regression_invariants` / `assert_no_sidecar_invariants`:

* `Run 074: VERDICT=applied` is emitted (the existing v1 / pre-v2
  path still works).
* No `Run 138` v2 verdict line is emitted (neither acceptance nor
  rejection — proof the v2 dispatch did not run).
* For R6 the post-SIGHUP marker is `"record_version": 1` (v1
  marker preserved end-to-end). For R7 no marker file exists at
  all (the legacy no-sidecar path writes neither a v1 nor a v2
  marker).

**Repeated SIGHUP serialization (R8)** — captured in
`assert_repeated_sighup_invariants`:

* Five `kill -HUP` are delivered against the same PID. At least
  one `Run 074: VERDICT=applied` line is observed (the Run 074
  in-progress guard is exercised end-to-end on the same PID).
* No `.tmp` marker sibling left behind.

**Cross-scenario observability invariants** — asserted by the
harness against **every** scenario's stderr:

* No `live inbound 0x05` line.
* No `peer-driven live apply` line.
* No `snapshot/restore v2` / `snapshot-restore v2` line.
* No `KMS` / `HSM` line.
* No `signing-key (rotation|revocation) lifecycle` line.
* No `falling back to --p2p-trusted-root` / `trusted-root
  fallback` line.

## R5 — release-binary infeasibility (partial-positive)

Scenario R5 (marker-persist failure **after** the Run 070
`commit_sequence` boundary returns `Ok`) is **release-binary-
infeasible** without either source modification or racy
filesystem-permission tricks that would themselves taint the
evidence. The same partial-positive treatment was applied in
Run 135 R4 and Run 137 R-low-block. Coverage is preserved by:

* The Run 138 source-level orchestration shape: the post-commit
  persist is keyed exclusively off the `Ok(applied)` return of
  `apply_validated_candidate_with_previous` — see
  `crates/qbind-node/src/pqc_live_trust_reload.rs`. Persist
  failure surfaces as
  `LiveReloadOutcome::MarkerPersistFailureAfterCommitV2 {
  applied, marker_error }` whose `is_fatal()` returns `true`, so
  the binary's SIGHUP task initiates graceful shutdown — same
  fatal shape as the v1 Run 121 fatal case.
* The corresponding Run 138 integration test:
  `run138_r6_v2_marker_persist_failure_after_commit_is_fatal`
  (unix-only) in
  `crates/qbind-node/tests/run_138_sighup_v2_authority_marker_tests.rs`.
* The existing Run 074 commit-failure regression coverage in
  `crates/qbind-node/tests/run_074_pqc_trust_bundle_live_reload_tests.rs`
  proves the apply pipeline tolerates commit / persist failure
  ordering boundaries.

The Run 139 release binary inherits this property by construction
because Run 139 does not modify the controller — the same
`LiveReloadController::try_trigger_with_now` entry point that the
Run 138 source/test wiring lands on is the same entry point the
binary's SIGHUP signal-handler task calls in `main.rs`.

## Marker / sequence SHA-256 attestation

The `marker_hashes/marker_hashes.csv` file in the evidence archive
records the pre/post SHA-256 of every scenario's on-disk marker
and trust-bundle sequence file. The expected shape (asserted by
the harness):

| Class      | marker SHA pre/post | sequence SHA pre/post |
|------------|---------------------|-----------------------|
| accept-v2  | **changed**         | **changed**           |
| idempotent | **identical**       | identical             |
| reject-v2  | **identical**       | **identical**         |
| accept-v1  | identical (R6) / absent (R7) | changed       |

This is captured for every scenario in the archive.

## Captured metadata

Captured in `summary.txt`:

* `outdir` — absolute path of the evidence archive.
* `repo` — absolute path of the source tree.
* `git_commit` — `git rev-parse HEAD` of the source tree the
  binary was built from.
* `rustc` / `cargo` — toolchain version strings.
* `qbind-node_sha256` and `qbind-node_build_id` — SHA-256 of the
  binary the scenarios were driven against, and its ELF `Build
  ID` (binds the evidence to a specific built artifact).
* `fixture-helper_sha256` and `fixture-helper_build_id` — same
  for the Run 133 fixture-helper release example.
* Exact CLI command template each scenario executed.
* Per-scenario `rc=… class=… pid=…` lines.

## Validation commands executed (Run 139 session)

All commands run against this PR's worktree
(`x86_64-unknown-linux-gnu`, `rustc 1.x` per `rust-toolchain.toml`):

```
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node --example run_133_v2_validation_only_fixture_helper
bash scripts/devnet/run_139_sighup_v2_live_reload_release_binary.sh \
     docs/devnet/run_139_sighup_v2_live_reload_release_binary
cargo test  -p qbind-node --test run_138_sighup_v2_authority_marker_tests
cargo test  -p qbind-node --test run_121_sighup_authority_marker_tests
cargo test  -p qbind-node --test run_074_pqc_trust_bundle_live_reload_tests
cargo test  -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests
cargo test  -p qbind-node --lib pqc_authority_marker_acceptance::
cargo test  -p qbind-node --lib
```

The release-binary harness emits `[run139] PASS: Run 139 evidence
captured under …` on a successful run; any per-scenario invariant
failure surfaces as a `FAIL:` line and the harness exits non-zero.

## Drift audit

Run 139 did not introduce any of the following:

* No new CLI flags. No CLI flag rename or semantic change.
* No new metric families. No new metric label cardinality.
* No new `AuthorityStateUpdateSource` variants (Run 139 reuses
  the existing `SighupReload` variant via the Run 138 wiring).
* No new trust-bundle / ratification-sidecar / peer-candidate
  / authority-marker / trust-bundle-sequence schema fields.
* No new wire-format frames. No change to any existing frame's
  byte layout.
* No new fixture helper (Run 139 reuses the
  `run_133_v2_validation_only_fixture_helper` release example).
* No production runtime source modified.
* No tests modified.

## Verdict

**Strongest-positive** for the v2 SIGHUP live-reload release-binary
matrix (A1–A4, R1–R4, R6–R8 — every scenario `pass`), with the
documented **partial-positive** treatment for R5 (release-binary-
infeasible; covered by the Run 138 source-level
orchestration shape and the
`run138_r6_v2_marker_persist_failure_after_commit_is_fatal`
integration test). No production runtime source changed; no
schema changed; no wire format changed; no metric changed.

## What this run does NOT prove

* That a snapshot / restore round-trip preserves the v2 marker.
* That a peer-delivered v2 trust-bundle is accepted via the live
  inbound 0x05 surface.
* That a peer-driven (non-SIGHUP) live trust-bundle apply path
  exists or is safe.
* That a signing-key rotation / revocation lifecycle has been
  exercised on the release binary.
* Anything about KMS / HSM custody, MainNet governance, full C4,
  or C5.

All of the above remain explicit Run 140+ scope.
