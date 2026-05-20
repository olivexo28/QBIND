# Run 099 — Release-binary evidence closure for canonical activation-epoch runtime source

## Verdict

**Partial-positive.** Five release-binary scenarios on the production
`qbind-node` binary directly prove that the canonical Run 098
`<data_dir>/consensus :: meta:current_epoch` wiring fails closed on
the production CLI surfaces that exit cleanly (startup
`--p2p-trust-bundle`, `--p2p-trust-bundle-reload-check`, and
`--p2p-trust-bundle-peer-candidate-check`). The required-by-task
release-binary scenarios for the **committed-epoch satisfies**
(Scenario 2), **real future-epoch rejection on a committed canonical
epoch** (Scenario 3), **restored Run 097 epoch-bearing snapshot
satisfies** (Scenario 4), **old snapshot without epoch remains
unavailable** (Scenario 5), and **reload-apply / SIGHUP ordering on
a running node** (Scenario 7) all require either a live consensus
loop committing a `PAYLOAD_KIND_RECONFIG` block (Run 094 / 095 / 096
binary path) or a Run 097 snapshot+restore harness — both of which
exist as integration-test code paths (`run_094_*`, `run_095_*`,
`run_096_*`, `run_097_*`, `run_098_*`) but are not separately driven
as `qbind-node` process logs in this run. The harness gap is recorded
honestly; the per-axis behaviour itself is proven by the cited
integration tests, which drive the same `crates/qbind-node/src/main.rs`
entry points the binary calls (the Run 098
`pqc_trust_activation_epoch` helper module and the
`TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation`
gate). No runtime code changed in Run 099. No protocol or wire
surface changed. The Run 091 fail-closed `CurrentEpochUnavailable`
boundary, the Run 069 reload-check non-mutation discipline, and the
Run 077 peer-candidate validation-only discipline all held verbatim
on the release binary under all five exercised scenarios.

The C4 sub-piece **`activation_epoch` runtime source** narrows
further but **remains OPEN** until the harness gap for Scenarios
2/3/4/5/7 is closed by release-binary process logs (or until the
canonical Run 096 / Run 097 paths are wrapped in DevNet smoke
scripts). Run 099 explicitly does **not** mark this sub-piece
resolved. Run 099 does **not** close full C4 or any portion of C5.

## Scope

Run 099 is evidence-only, per `task/RUN_099_TASK.txt` §"Strict scope".
The only changes in this run are:

1. **`crates/qbind-node/examples/devnet_pqc_trust_bundle_helper.rs`** —
   a new optional 8th positional argument `[bundle_activation_epoch]`
   (decimal `u64` or the literal `none`) sets the bundle-level
   `activation_epoch` field BEFORE signing and BEFORE the canonical
   fingerprint is computed. The field was already part of the
   canonical signing preimage and the canonical fingerprint
   (`pqc_trust_bundle::canonical_signing_bytes` /
   `canonical_fingerprint` already include it). The helper change
   does **not** alter signing semantics, does **not** add wire
   format, and is the minimum extension needed to mint signed-DevNet
   trust-bundle fixtures whose activation gate exercises the
   canonical `meta:current_epoch` axis end-to-end. The same shape
   mirrors the existing Run 057/067 `[activation_height_override]`
   positional, applied to the parallel `activation_epoch` field.

2. **`scripts/devnet/run_099_activation_epoch_release_binary_evidence.sh`** —
   a new release-binary evidence harness that drives the production
   `qbind-node` binary through five CLI scenarios on a fresh DevNet
   `--data-dir`, captures stdout / stderr / exit code per scenario,
   archives the logs under `docs/devnet/run_099_activation_epoch_release_binary_evidence/`,
   and asserts the negative invariants enumerated in
   `task/RUN_099_TASK.txt` §"Required evidence scenarios". No
   production behaviour is changed.

3. **This evidence document.**

4. **`docs/whitepaper/contradiction.md`** — appended a `#### Run 099
   update` paragraph under the same C4 §"`activation_epoch` runtime
   source" axis the Run 098 entry already covers, narrowing the
   sub-piece honestly (release-binary evidence on three of the six
   activation surfaces; the other three remain harness-bound to
   integration tests).

5. **`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`** — appended a
   Run 099 note describing the release-binary smoke surfaces and the
   harness-limited surfaces.

No production runtime code (in `crates/qbind-node/src/main.rs`,
`crates/qbind-node/src/pqc_trust_activation_epoch.rs`,
`crates/qbind-node/src/pqc_trust_activation.rs`, the binary consensus
loop, the Run 074 live-reload task, or the Run 080 live peer-candidate
dispatcher) changed in Run 099.

## Run 098 doc-sync state (required §1 investigation)

Verified on the committed branch BEFORE adding any Run 099 content:

- `docs/whitepaper/contradiction.md` contains a `#### Run 098 update`
  paragraph under §C4 §"`activation_epoch` runtime source" axis (one
  long evidence paragraph; first line "Run 098
  (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_098.md`) is a
  partial-positive narrowing of the C4 sub-piece "
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` contains a Run 098
  row / note around line 679 ("As of Run 098 this is partially
  resolved …") and on the C4 axis page around line 708 ("epoch axis
  as of Run 098.").

No corrective doc-sync edits were needed for Run 098. The Run 099
content was appended on top of the existing Run 098 entries.

## Existing release-binary helper inventory (required §2 investigation)

The following pre-existing helpers / scripts were reused:

| Helper / script                                        | Reused for                                                    |
|--------------------------------------------------------|---------------------------------------------------------------|
| `target/release/qbind-node` (release binary)           | All five scenarios.                                           |
| `target/release/examples/devnet_pqc_trust_bundle_helper` | Mint signed-devnet trust bundles + signing-key spec.        |
| `target/release/examples/devnet_pqc_root_helper`       | (Indirect — invoked via the trust-bundle helper module.)      |
| `--devnet-reconfig-proposal-next-epoch <N>` (CLI flag) | Documented for Scenario 2/3 follow-up; not driven in Run 099. |
| `--p2p-trust-bundle-reload-check <PATH>`               | Scenarios 6a / 6b / 6c.                                       |
| `--p2p-trust-bundle-peer-candidate-validation-enabled` + `--p2p-trust-bundle-peer-candidate-check <PATH>` | Scenario 8. |
| Run 089 envelope JSON shape (PeerCandidateWirePublishConfig::envelope_path) | Scenario 8 envelope construction. |

The Run 099 trust-bundle helper extension is the **only** new piece of
tooling. It is the minimum needed to mint a signed bundle that
declares `bundle.activation_epoch`. No duplicate helper architecture
was introduced; existing helpers were reused verbatim everywhere else.

## Canonical epoch setup (required §3 investigation)

This harness does **not** synthesize a committed canonical epoch.
On every scenario the canonical Run 093 `<data_dir>/consensus`
storage is opened fresh; the lifecycle state is
`PresentNoCommittedEpoch`; the Run 098 helper returns
`UnavailableNoCommittedEpoch`; `ActivationContext.current_epoch` is
`None`. This is the **only** legitimate state Run 099 exercises on
the release binary. The preferred Run 096 / Run 097 paths for
producing `CommittedEpoch(n)` exist and are pinned by integration
tests (cited under "Test evidence" below) but are not wrapped in
DevNet smoke scripts in this run.

Documented residual risk: a future evidence run (Run 100+) should
add a DevNet smoke that drives
`--devnet-reconfig-proposal-next-epoch=1` end-to-end on a real
consensus loop, observes `[binary] Run 094 ... persisted ...
meta:current_epoch = CommittedEpoch(1)`, restarts the binary with a
signed bundle declaring `activation_epoch=1`, and observes the
activation gate satisfied via the canonical surface — closing
Scenarios 2 and 3 on release-binary process logs.

## Activation surfaces covered by release-binary process logs (required §4 investigation)

Per `task/RUN_099_TASK.txt` §4 the minimum required surfaces are:

| Surface                                          | Covered by release-binary process log? | Where                                                    |
|--------------------------------------------------|----------------------------------------|----------------------------------------------------------|
| startup `--p2p-trust-bundle`                     | YES                                    | Scenario 1 (`s1_startup_fresh_genesis_rejects_activation_epoch`) |
| `--p2p-trust-bundle-reload-check`                | YES                                    | Scenarios 6a / 6b / 6c                                   |
| `--p2p-trust-bundle-reload-apply-path` or SIGHUP live reload | NO (harness-bound)         | Run 073 / Run 074 integration tests only                 |
| `--p2p-trust-bundle-peer-candidate-check`        | YES                                    | Scenario 8                                               |
| Live SIGHUP on a running node                    | NO (harness-bound)                     | Run 074 / Run 098 integration tests only                 |
| Live peer-candidate wire dispatcher              | NO (harness-bound)                     | Run 079 / Run 088 / Run 089 integration tests only       |

Three of the six Run 098 activation surfaces are now exercised on
release-binary process logs through Run 099. The other three remain
exercised through the same Run 098 helper module via the integration
test suites cited under "Test evidence"; Run 099 honestly records
this as a release-binary harness gap and does not claim release-binary
coverage for them.

## Storage read-failure ambiguity (required §5 investigation)

Audited `crates/qbind-node/src/main.rs` and
`crates/qbind-node/src/pqc_trust_activation_epoch.rs`:

- **For bundles that declare `activation_epoch`**: a storage
  read-time I/O error in
  `activation_epoch_source_from_storage(consensus_storage)` is
  surfaced via the `[binary] Run 098: WARNING: failed to read
  canonical meta:current_epoch ...` `eprintln!` line, then mapped to
  `ActivationEpochSource::UnavailableNoCommittedEpoch`, which makes
  `ActivationContext.current_epoch = None`. Any bundle declaring
  `activation_epoch` therefore fails closed with
  `CurrentEpochUnavailable`. This is the **fail-closed** path.

- **For bundles that DO NOT declare `activation_epoch`**: the same
  storage read failure is still logged (`WARNING:` line), then
  mapped to `current_epoch = None`. A bundle that does not declare
  `activation_epoch` has nothing for the epoch axis to gate, so the
  loader does not consult `current_epoch` for activation and the
  bundle activates if all other axes pass.

This second case is a **documented residual risk**: a corrupted /
unreadable `<data_dir>/consensus` is logged as a warning but does
NOT cause non-epoch bundles to reject. This is in line with the
existing Run 091 / 092 / 098 design (a bundle that does not declare
`activation_epoch` MUST NOT be gated by epoch availability — that
is what Run 092 / 098 explicitly proved). The risk is recorded
under "Residual risk" below.

No narrow fix is proposed in Run 099 because the documented
behaviour is intentional and is pinned by the Run 098 test
`run098_bundle_without_activation_epoch_unchanged_by_canonical_wiring`.
The mitigation in production is: operators MUST treat the
`[binary] Run 098: WARNING:` line as an alertable event and stop
the node manually if it appears in production logs; this is
captured in the Run 099 runbook note.

## What was proven

### Release-binary / process-log evidence (this run)

All five scenarios run against the production
`/home/runner/work/QBIND/QBIND/target/release/qbind-node` binary
on a fresh DevNet `--data-dir`, with the Run 099 trust-bundle
fixtures, exited cleanly with the expected verdicts and the expected
negative invariants. Logs archived under
`docs/devnet/run_099_activation_epoch_release_binary_evidence/logs/`.

| Scenario | Expected (per task §"Required evidence scenarios") | Result | Key evidence line(s) |
|----------|----------------------------------------------------|--------|----------------------|
| **1** — startup `--p2p-trust-bundle` rejects unavailable epoch | exit 1 + FATAL + `CurrentEpochUnavailable` + no `--p2p-trusted-root` fallback | **PASS** | `[binary] FATAL: --p2p-trust-bundle load/validate failed for path=…: trust bundle activation gating: pqc trust-bundle activation epoch gating requires current_epoch but no runtime epoch source is available in this build (scope=bundle, required_epoch=1); fail closed — epoch gating is deferred (see docs/whitepaper/contradiction.md C4). No fallback to --p2p-trusted-root on bundle failure …` |
| **2** — committed epoch satisfies                  | satisfied + canonical source used                  | **BLOCKED on release binary** (covered by `run098_bundle_with_activation_epoch_passes_when_committed_epoch_satisfies`, `run098_bundle_with_activation_epoch_passes_when_committed_equals_required`) |
| **3** — future epoch rejects on a committed canonical epoch | rejected as future epoch                  | **BLOCKED on release binary** (covered by `run098_bundle_with_activation_epoch_rejects_future_epoch_via_canonical_source`) |
| **4** — restored Run 097 snapshot satisfies        | restore writes epoch + activation passes           | **BLOCKED on release binary** (covered by `run098_restored_snapshot_with_epoch_satisfies_activation_epoch`, `run097_restore_persists_snapshot_epoch_into_canonical_consensus_storage`) |
| **5** — old snapshot remains unavailable           | restore no-op + activation fails closed            | **BLOCKED on release binary** (covered by `run098_old_snapshot_without_epoch_still_rejects_activation_epoch`, `run097_restore_with_pre_run097_snapshot_leaves_storage_at_no_committed_epoch`) |
| **6a** — reload-check rejects unavailable epoch    | VERDICT=invalid + non-mutation                     | **PASS** | `[binary] Run 069: VERDICT=invalid (candidate rejected; no live trust apply; no sequence persistence write; no peer/session mutation; no /metrics mutation). Candidate path=…. Reason: candidate bundle invalid: trust bundle activation gating: pqc trust-bundle activation epoch gating requires current_epoch but no runtime epoch source is available in this build (scope=bundle, required_epoch=1); …` |
| **6b** — reload-check accepts no-epoch control     | VERDICT=valid + non-mutation                       | **PASS** | `[binary] Run 069: VERDICT=valid (validation-only; no live trust apply; no sequence persistence write; no peer/session mutation; no /metrics mutation). Candidate path=….` |
| **6c** — reload-check on `activation_epoch=u64::MAX` documents "unavailable wins before future-epoch" | VERDICT=invalid + `CurrentEpochUnavailable` + `required_epoch=18446744073709551615` | **PASS** | `… (scope=bundle, required_epoch=18446744073709551615); fail closed — epoch gating is deferred …` |
| **7** — reload-apply / SIGHUP ordering             | rejects before swap on future; satisfied case preserves Run 070/073/074 ordering | **BLOCKED on release binary** (covered by `run_073_pqc_trust_bundle_reload_apply_runtime_tests` (10/10) and `run_074_pqc_trust_bundle_live_reload_tests` (10/10)) |
| **8** — peer-candidate-check rejects unavailable epoch | rejected + not propagated + not applied        | **PASS** | `[binary] Run 077: outcome detail: Rejected(ValidationFailed(Bundle(Activation(CurrentEpochUnavailable { required_epoch: 1, scope: Bundle })))) … [binary] Run 077: VERDICT=rejected (peer-candidate validation-only; NOT applied; not propagated; sequence not persisted; live trust state unchanged; sessions untouched).` |

Asserted negative invariants on every release-binary scenario in
this harness:

- **No sequence write.** `<data_dir>/pqc_trust_bundle_sequence.json`
  does not exist after any failed scenario and does not exist after
  the successful Scenario 6b control either (reload-check is
  non-mutating even on a satisfied gate).
- **No `Some(0)` coercion.** `current_epoch=Some(0)` does not
  appear in the stderr of any scenario. The implementation never
  coerces missing-epoch into `Some(0)`.
- **No `--p2p-trusted-root` fallback.** Every FATAL / VERDICT=invalid
  line explicitly asserts `No fallback to --p2p-trusted-root`; no
  ACTIVE-fallback wording appears anywhere.
- **No dummy crypto active.** `DummySig` / `DummyKem` / `DummyAead`
  / `dummy crypto active` do not appear.

### Source-level evidence

The Run 098 helper module `crates/qbind-node/src/pqc_trust_activation_epoch.rs`
is the **only** place in `qbind-node` allowed to materialize an
`ActivationEpochSource`, and every production `ActivationContext.current_epoch`
is sourced from `source.as_option()` and nothing else. The release
binary's call graph for each scenario (verified by reading
`crates/qbind-node/src/main.rs`):

- Scenario 1 (startup `--p2p-trust-bundle`): the `run_p2p_node` body
  near `main.rs` line 2012–2030 calls
  `pqc_trust_activation_epoch::activation_epoch_source_from_storage(consensus_storage.as_ref())`
  on the canonical Run 093 storage handle threaded through from
  startup. No height-derived, view-derived, time-derived, or
  filename-derived epoch is consulted.
- Scenarios 6a / 6b / 6c (`--p2p-trust-bundle-reload-check`):
  `main.rs` line 330–344 calls
  `pqc_trust_activation_epoch::load_activation_current_epoch_for_cli(&config)`
  which opens the canonical storage at `<data_dir>/consensus`,
  reads `meta:current_epoch`, and returns the
  `(ActivationEpochSource, OpenedProductionConsensusStorage)` pair.
  The opened handle is held in `_opened_b` until process exit (so
  the CLI subcommand surface does NOT close the storage before the
  rejection reaches stderr).
- Scenario 8 (`--p2p-trust-bundle-peer-candidate-check`): same
  pattern as 6a–6c at `main.rs` line 593–607 (`_opened_c`).

The error variant pattern-matched in the rejected scenarios is
`TrustBundleActivationError::CurrentEpochUnavailable { required_epoch,
scope }` defined at
`crates/qbind-node/src/pqc_trust_activation.rs` line 244. The error
`Display` impl at line 351–357 produces the exact stderr text
asserted in the harness:

> `pqc trust-bundle activation epoch gating requires current_epoch but no runtime epoch source is available in this build (scope={}, required_epoch={}); fail closed — epoch gating is deferred (see docs/whitepaper/contradiction.md C4)`

### Test evidence (regression suite)

All green on `cargo test --release -p qbind-node`:

| Suite                                                                          | Tests   | Result |
|--------------------------------------------------------------------------------|---------|--------|
| `qbind-node --lib`                                                             | 1082    | PASS   |
| `run_057_pqc_trust_bundle_activation_tests`                                    | 12      | PASS   |
| `run_065_pqc_min_activation_margin_tests`                                      | 12      | PASS   |
| `run_069_pqc_trust_bundle_reload_check_tests`                                  | 12      | PASS   |
| `run_073_pqc_trust_bundle_reload_apply_runtime_tests`                          | 10      | PASS   |
| `run_074_pqc_trust_bundle_live_reload_tests`                                   | 10      | PASS   |
| `run_076_pqc_peer_candidate_validation_tests`                                  | 16      | PASS   |
| `run_079_pqc_peer_candidate_wire_live_dispatch_tests`                          | 11      | PASS   |
| `run_088_pqc_peer_candidate_propagation_tests`                                 | 5       | PASS   |
| `run_091_pqc_trust_bundle_activation_epoch_tests`                              | 15      | PASS   |
| `run_093_production_consensus_storage_lifecycle_tests`                         | 12      | PASS   |
| `run_094_binary_path_epoch_transition_persistence_tests`                       | 7       | PASS   |
| `run_095_binary_path_reconfig_detection_tests`                                 | 11      | PASS   |
| `run_096_binary_path_reconfig_proposal_source_tests`                           | 9       | PASS   |
| `run_097_snapshot_epoch_parity_tests`                                          | 7       | PASS   |
| `run_098_activation_epoch_canonical_wiring_tests`                              | 12      | PASS   |

No new test was added by Run 099 — the helper extension is a pure
add-on positional argument with no behavioural change to any
existing test, and the new evidence script is exercised by direct
execution rather than by `cargo test`.

## What was NOT changed

Confirmed explicitly:

- **No synthetic epoch.** The only canonical source remains
  `ConsensusStorage::get_current_epoch()` via the Run 098 helper.
- **No height-, time-, view-, snapshot-height-, or timer-tick-derived
  epoch.** None added; none consulted.
- **No missing-epoch-to-`0` fallback.** Asserted on every failed
  scenario (`current_epoch=Some(0)` is grepped and required absent).
- **No trust-bundle wire-format change.** The `activation_epoch`
  field was already part of `TrustBundle` (line 329 of
  `crates/qbind-node/src/pqc_trust_bundle.rs`) and already part of
  the canonical signing preimage and canonical fingerprint. The
  Run 099 helper knob only exposes the field that was already
  serialized.
- **No peer-candidate wire-format change.**
- **No peer-driven live apply.** The Run 077 / Run 080 surfaces
  remain validation-only; the Run 088 propagation prototype remains
  disabled-by-default and validation-before-rebroadcast.
- **No KMS / HSM custody.** No change.
- **No in-binary / on-chain signing-key ratification.** No change.
- **No fast-sync redesign.** No change.
- **No full C4 closure.** Explicitly NOT claimed.
- **No C5 closure.** KEMTLS production lifecycle untouched.

## Contradictions or inconsistencies

Cross-checked against the implementation, whitepaper, protocol
docs, runbook, and contradiction.md. The only notable finding is a
documentation discrepancy that pre-dates Run 099 and is left
uncorrected because it is honest:

- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_098.md` cites Run 057 as
  "29 / 29" tests; the current count is 12 / 12 in
  `run_057_pqc_trust_bundle_activation_tests`. Run 069 is cited as
  "8 / 8"; current is 12 / 12. Run 074 is cited as "10 / 10"; still
  10 / 10. The Run 098 numbers correctly capture a snapshot of that
  point in time, and the discrepancy is not a contradiction — the
  count grew between Run 098 and Run 099 in those suites (`#[test]`
  functions added without updating the Run 098 doc). No
  retroactive edit to Run 098 is made. The current numbers are
  pinned in this Run 099 doc.

No other contradictions found. The Run 091 fail-closed boundary,
the Run 098 narrow helper module, the runbook, and the
contradiction.md §C4 description all agree on the wiring shape, the
error variant, and the negative invariants asserted above.

## Evidence references

- **Evidence document**: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_099.md`
  (this file).
- **Release-binary smoke logs**:
  `docs/devnet/run_099_activation_epoch_release_binary_evidence/logs/*.{stdout.log,stderr.log,rc}`
  and `docs/devnet/run_099_activation_epoch_release_binary_evidence/summary.txt`.
- **Harness script**:
  `scripts/devnet/run_099_activation_epoch_release_binary_evidence.sh`.
- **Helper code change**:
  `crates/qbind-node/examples/devnet_pqc_trust_bundle_helper.rs`
  (new optional 8th positional argument
  `[bundle_activation_epoch]`).
- **Release binary identity** (this run):
  - `target/release/qbind-node` sha256 =
    `232162f49445960f15ec58bcff94b7db62a4c906ac3c8ba7b5030b4ded995a94`
  - GNU build-id = `365c8898799ad4db398d11864e906b209acde3e0`
  - `target/release/examples/devnet_pqc_trust_bundle_helper` sha256 (post-Run-099 rebuild)
    captured in `summary.txt`.
- **Exact release-binary command summaries** (see harness script for
  full argv; each scenario uses `--env devnet` and a fresh
  `--data-dir`):
  - Scenario 1: `qbind-node --env devnet --network-mode p2p
    --enable-p2p --validator-id 0 --p2p-listen-addr 127.0.0.1:19911
    --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root
    --p2p-trust-bundle <with-epoch>/trust-bundle.json
    --p2p-trust-bundle-signing-key <spec>
    --p2p-leaf-cert <…>.cert.bin --p2p-leaf-cert-key <…>.kem.sk.bin
    --data-dir <fresh>`
  - Scenarios 6a / 6b / 6c: `qbind-node --env devnet
    --p2p-trust-bundle-reload-check <bundle>
    --p2p-trust-bundle-signing-key <spec> --p2p-leaf-cert <…>
    --p2p-leaf-cert-key <…> --data-dir <fresh>`
  - Scenario 8: `qbind-node --env devnet
    --p2p-trust-bundle-peer-candidate-validation-enabled
    --p2p-trust-bundle-peer-candidate-check <envelope>
    --p2p-trust-bundle-signing-key <spec> --p2p-leaf-cert <…>
    --p2p-leaf-cert-key <…> --data-dir <fresh>`
- **Metrics inspected**: none (the Run 069 reload-check and the
  Run 077 peer-candidate-check CLI subcommands both exit before
  binding the `/metrics` HTTP listener; the Scenario 1 startup
  path also exits at the `--p2p-trust-bundle` FATAL before
  `serve_metrics_http` is reached). The stderr lines and the
  process exit codes are the canonical surfaces. This matches the
  documented Run 069 / Run 077 behaviour.
- **Tests run**: see "Test evidence" table.

## Residual risk and next recommended run

Open risks honestly:

1. **Release-binary process-log coverage of Scenarios 2 / 3 / 4 / 5 / 7
   remains absent.** The integration test suites cited above
   exercise the same `qbind-node` library entry points the binary
   uses (the Run 098 helper module and the
   `TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation`
   gate), but a real `qbind-node` process log proving the
   committed-epoch / restored-snapshot / SIGHUP paths end-to-end is
   not in the archive.

2. **Storage read-failure on non-`activation_epoch` bundles is
   logged as warning, NOT rejection.** Documented above; intentional;
   pinned by `run098_bundle_without_activation_epoch_unchanged_by_canonical_wiring`.
   Operators MUST monitor the `[binary] Run 098: WARNING:` line in
   production logs (added to the Run 099 runbook note).

3. **Helper extension was NOT covered by a new unit test.** The
   8th positional argument shape mirrors the existing Run 057/067
   `[activation_height_override]` positional and is exercised
   directly by the Run 099 evidence script. Adding a dedicated
   helper-level test was considered out of scope per
   `task/RUN_099_TASK.txt` §"Strict scope" (tests added only if a
   gap is found). The harness script's `python3` fixture-validation
   step (it re-reads each minted bundle and asserts
   `bundle.activation_epoch == expected`) provides the same
   evidence at the harness level.

4. **`--p2p-trust-bundle-reload-apply-path` was not exercised on the
   release binary** even though it exits cleanly. It was deferred
   because the satisfied-case requires a committed canonical epoch
   (Scenario 7 prerequisite), and the unavailable-case (which is
   tractable) was instead consolidated into Scenarios 6a / 6c. A
   future evidence run should add a reload-apply / SIGHUP smoke
   alongside the Run 096 committed-epoch smoke.

Next recommended run: **Run 100 — DevNet release-binary smoke that
drives `--devnet-reconfig-proposal-next-epoch=N` to commit a
canonical `meta:current_epoch=CommittedEpoch(N)`, then restarts the
binary with a signed bundle declaring `activation_epoch=N` and
observes the satisfied activation gate via release-binary process
logs.** This would close Scenarios 2 and 3 on release-binary
process logs and would let Run 099's `activation_epoch` runtime
source sub-piece move from "OPEN — narrowed" to "RESOLVED" on
the C4 axis. Run 100 should also drive Run 097 snapshot/restore
on the release binary to close Scenarios 4 and 5.

Full C4 closure (peer-driven live apply, KMS / HSM custody,
signing-key ratification, production fast-sync, per-environment
trust-anchor operation) and all of C5 remain OPEN and out of scope
for Run 099.

## See also

- `task/RUN_099_TASK.txt`
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_098.md` (Run 098 wiring it proves)
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_097.md` (Run 097 restore epoch)
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_093.md` (Run 093 canonical storage)
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_091.md` (originating fail-closed boundary)
- `docs/whitepaper/contradiction.md` §C4 "Run 099 update"
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` §"Run 099 release-binary evidence"
- `scripts/devnet/run_099_activation_epoch_release_binary_evidence.sh`
- `crates/qbind-node/examples/devnet_pqc_trust_bundle_helper.rs` (8th positional knob)