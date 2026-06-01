# Run 162 — Release-Binary Lifecycle ENFORCEMENT Evidence for v2 Marker-Decision Surfaces

## Scope

Run 162 produces **release-binary lifecycle enforcement evidence** for
the Run 159 typed v2 bundle-signing-key lifecycle validator
(`qbind_node::pqc_authority_lifecycle::validate_v2_lifecycle_transition`)
now that Run 161 has wired the validator into the shared v2
marker-decision helper
(`qbind_node::pqc_authority_marker_acceptance::decide_marker_acceptance_v2`).

Run 162 supersedes Run 160's "zero production caller" partial-positive
boundary by proving on the real `target/release/qbind-node` that
lifecycle accepts and lifecycle rejects flow through at least one
**validation-only** v2 marker-decision surface (`reload-check`) and at
least one **mutating** v2 marker-decision surface (`reload-apply`), with:

* the **lifecycle validator's production call site** demonstrably
  present in `crates/qbind-node/src/pqc_authority_marker_acceptance.rs`
  (`decide_marker_acceptance_v2`) after Run 161;
* lifecycle-accepted candidates passing through to Run 070 apply, Run
  055 sequence commit, and post-commit v2 marker persistence; and
* lifecycle-rejected candidates failing closed with no live trust swap,
  no session eviction, no Run 055 sequence write, no v2 marker write,
  no `.tmp` residue, no fallback to `--p2p-trusted-root`, and no active
  `DummySig` / `DummyKem` / `DummyAead`.

## Verdict

**release-binary lifecycle enforcement EVIDENCE captured: lifecycle
accepts and rejects are now observable on the real release binary
through both a validation-only and a mutating v2 marker-decision
surface; Run 160's zero-call-site boundary is superseded.**

Run 162 does **not** claim full **C4** closure and does **not** claim
**C5** closure. Governance, KMS/HSM, and validator-set rotation remain
unimplemented. MainNet remains refused unconditionally for peer-driven
apply (cited from Run 151 / Run 158 release-binary evidence; this
harness does not enable MainNet on any surface).

## Source delta

* `scripts/devnet/run_162_authority_lifecycle_release_binary_enforcement.sh`
  — new release-binary harness (additive; no production runtime
  caller).
* `docs/devnet/run_162_authority_lifecycle_release_binary_enforcement/`
  — new evidence archive (this file + `summary.txt` are tracked;
  everything else is `.gitignore`d, mirroring Run 153 / 155 / 156 /
  158 / 160).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_162.md` — canonical evidence
  report.
* Narrow doc updates to:
  * `docs/whitepaper/contradiction.md`,
  * `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`,
  * `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`,
  * `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`.

**No production runtime source change.** No `main.rs` / `cli.rs` edit.
No CLI flag added or renamed. No SIGHUP / startup-trust-bundle / live
`0x05` dispatcher / drain-once code path change. No `LivePqcTrustState`
mutation outside the existing Run 070 apply path. No sequence write
outside the existing Run 055 path. No authority-marker write outside
the existing post-commit boundary. No new wire format. No
trust-bundle / ratification-sidecar / authority-marker / sequence-file
/ peer-candidate-envelope schema change. No new metric family. No
KMS / HSM. No governance implementation. No MainNet enablement. No
autonomous background drain. No automatic apply on receipt. No
peer-majority authority. No weakening of validation-only or
propagation-only behaviour.

## Surfaces exercised

| Category          | Surface                                | CLI flags driven                                                                                                |
|-------------------|----------------------------------------|------------------------------------------------------------------------------------------------------------------|
| validation-only   | reload-check (Run 132 dispatch)        | `--p2p-trust-bundle-reload-check` + `--p2p-trust-bundle-ratification` + `--p2p-trust-bundle-allow-unratified-testnet-devnet` |
| mutating          | process-start reload-apply (Run 134)   | `--p2p-trust-bundle-reload-apply-enabled` + `--p2p-trust-bundle-reload-apply-path` + `--p2p-trust-bundle-ratification`       |

Both surfaces route through the single shared helper
`decide_marker_acceptance_v2`, which now invokes
`validate_v2_lifecycle_transition` per Run 161. SIGHUP, live inbound
`0x05`, startup `--p2p-trust-bundle` v2, and peer-driven drain-once
are documented as covered through the same shared helper at the
source/test level (Run 161 A1–A9 / R1–R20) but are not separately
re-driven on the release binary by Run 162; the task explicitly allows
the minimal `reload-check` + `reload-apply` matrix because they are
easier to drive deterministically than long-running SIGHUP or live
`0x05`.

## Lifecycle action coverage at the release-binary surface

| Action            | Release-binary surface accept                                                       | Release-binary surface reject                                                       | Source/test-only on release binary today |
|-------------------|---------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------|------------------------------------------|
| `ActivateInitial` | YES — A.A1 reload-check + B.A1 reload-apply                                          | n/a                                                                                   | NO                                       |
| `Rotate`          | YES — A.A2 reload-check + B.A2 reload-apply                                          | YES (via lower-sequence + same-sequence equivocation against rotated targets)         | NO                                       |
| `Retire`          | NOT REPRESENTABLE through reload-check / reload-apply CLI without sub-class metadata | NOT REPRESENTABLE (R9 retired-key reuse needs sub-class persisted-marker metadata)    | YES — cite Run 159 A3 / R9 + Run 161 A6  |
| `Revoke`          | wire-byte path covered by the existing equivocation/lower-sequence comparisons       | wire-byte path covered by R1 / R2                                                     | sub-class semantics: Run 159 A4 / R8     |
| `EmergencyRevoke` | NOT REPRESENTABLE through reload-check / reload-apply CLI without sub-class metadata | NOT REPRESENTABLE (R10 emergency-revoke replay needs sub-class metadata)              | YES — cite Run 159 A5 / R10 + Run 161 A8 |
| Idempotent        | YES — A.A6 reload-check + B.A6 reload-apply                                          | n/a                                                                                   | NO                                       |

The Run 159 typed validator interprets the lifecycle sub-class via the
local `revoked_key_metadata` byte prefix (`01`=Revoke, `02`=Retire,
`03`=EmergencyRevoke); the existing v2 ratification wire sidecar
(Run 130) does not surface this prefix as a CLI argument, so Retire /
EmergencyRevoke / sub-class-prefixed Revoke acceptance and the
sub-class-only rejection cases R6–R11 must continue to be cited from
Run 159 source/test coverage and Run 161 source/test integration
coverage. **The Run 162 reachability proof and the
`decide_marker_acceptance_v2` integration mean those Run 161 source/test
results are now exercised by the *same* helper that the release binary
calls** — i.e. Run 159/161 source/test results are no longer claims
about a dead-code module; they are claims about the production code
path.

## Required release-binary scenario matrix (driven by the harness)

The harness `scripts/devnet/run_162_authority_lifecycle_release_binary_enforcement.sh`
mints fixtures with the existing release-built `run_133_v2_validation_only_fixture_helper`
example (which produces the v2 ratification sidecars + baseline /
candidate trust bundles + seed markers used by Run 133 / Run 135) and
the existing release-built `run_160_authority_lifecycle_fixture_helper`
example (which produces the lifecycle marker corpus inherited from
Run 160). Each scenario data dir is captured in
`data_inventories/<scenario>.inventory.txt`, marker pre/post SHA-256s
in `marker_hashes/<scenario>.marker_{pre,post}.sha256`, sequence post
SHA-256 in `sequence_hashes/<scenario>.sequence_post.sha256`, exit
code in `exit_codes/<scenario>.exit_code`, and stdout/stderr in
`logs/<scenario>.{stdout,stderr}.log`.

### A. Validation-only (`reload-check`) scenarios

| ID                           | Scenario                                                                 | Expected outcome                              | Mutation? |
|------------------------------|--------------------------------------------------------------------------|-----------------------------------------------|-----------|
| `A_A1_reload_check_initial_accept`     | v2 ratify@seq=1, no marker (ActivateInitial accepted)             | rc=0; `reload-check v2 authority-marker check passed: no-persisted-marker-yet` | NONE      |
| `A_A2_reload_check_rotate_accept`      | v2 rotate@seq=2 over v2-seq=1 (Rotate accepted)                   | rc=0; `reload-check v2 authority-marker check passed: v2 upgrade-compatible 1 -> 2` | NONE      |
| `A_A6_reload_check_idempotent_accept`  | v2 ratify@seq=1 over v2-seq=1 (Idempotent accepted)               | rc=0; `reload-check v2 authority-marker check passed: v2 idempotent` | NONE      |
| `A_R1_reload_check_lower_sequence`     | v2 ratify@seq=1, v2-seq=2 marker (lower sequence rejected)        | rc=1; `Run 132: v2 lower sequence refused`    | NONE      |
| `A_R2_reload_check_equivocation`       | v2 ratify@seq=1 (different digest) over v2-seq=1 (equivocation)   | rc=1; `Run 132: v2 same-sequence different-digest refused` | NONE      |
| `A_R3_reload_check_wrong_environment`  | wrong-environment v2 sidecar (verifier rejection)                 | rc=1; `environment mismatch`                  | NONE      |
| `A_R4_reload_check_wrong_chain`        | wrong-chain v2 sidecar (verifier rejection)                       | rc=1; `chain_id mismatch`                     | NONE      |
| `A_R5_reload_check_wrong_genesis`      | wrong-genesis v2 sidecar (verifier rejection)                     | rc=1; `genesis_hash does not match runtime canonical genesis hash` | NONE      |
| `A_R12_reload_check_bad_signature`     | tampered-signature v2 sidecar (PQC verifier surrogate for non-PQC suite) | rc=1; `signature failed ML-DSA-44 PQC verification` | NONE      |

For every validation-only scenario, the harness asserts:

* no `pqc_trust_bundle_sequence.json` is created under the scenario data dir;
* no `pqc_authority_state.json` is created under the scenario data dir
  when no pre-seeded marker existed;
* pre-seeded marker bytes are byte-identical post-run when one was
  seeded;
* no `pqc_authority_state.json.tmp` sibling is left behind;
* no `trust-bundle candidate APPLIED live` / `VERDICT=applied` /
  `session_evictions=N≥1` / `SIGHUP` / `KMS|HSM` markers were emitted;
* no `falling back to --p2p-trusted-root` line was emitted.

### B. Mutating (`reload-apply`) scenarios

| ID                                       | Scenario                                                                  | Expected outcome                                                                                                                                            | Mutation                                                                       |
|------------------------------------------|---------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------|
| `B_A1_reload_apply_initial_accept`       | v2 ratify@seq=1, no marker (ActivateInitial accepted)                     | rc=0; `[run-134] reload-apply v2 ratification path SELECTED`; `trust-bundle candidate APPLIED live`; `sequence_commit=ok`; `VERDICT=applied`; `[run-134] v2 authority-marker persisted ... candidate latest_authority_domain_sequence=1` | sequence advances to 1; v2 marker persisted POST-commit; record_version=2; latest_lifecycle_action=ratify  |
| `B_A2_reload_apply_rotate_accept`        | v2 rotate@seq=2 over v2-seq=1 (Rotate accepted)                           | rc=0; same SELECTED + APPLIED + commit_ok + VERDICT=applied; `... candidate latest_authority_domain_sequence=2`                                              | sequence advances 1→2; v2 marker persisted POST-commit; latest_lifecycle_action=rotate                       |
| `B_A6_reload_apply_idempotent_accept`    | v2 ratify@seq=1 over v2-seq=1 (Idempotent accepted, no rewrite)           | rc=0; `[run-134] v2 authority-marker unchanged ... idempotent; no rewrite`                                                                                  | sequence file present; v2 marker bytes byte-identical to seed                  |
| `B_R1_reload_apply_lower_sequence`       | v2 ratify@seq=1, v2-seq=2 marker (lower sequence rejected)                | rc=1; `[run-134] FATAL: reload-apply refused by v2 authority-marker preflight`; `LowerV2SequenceRefused`                                                    | NONE — pre-seeded v2-seq=2 marker preserved bit-for-bit; no sequence write     |
| `B_R2_reload_apply_equivocation`         | v2 ratify@seq=1 (different digest) over v2-seq=1 (equivocation)           | rc=1; `... preflight refused`; `SameSequenceConflicting`                                                                                                    | NONE                                                                           |
| `B_R3_reload_apply_wrong_environment`    | wrong-environment v2 sidecar (verifier rejection at preflight)            | rc=1; `... preflight refused`; `environment mismatch`                                                                                                       | NONE                                                                           |
| `B_R12_reload_apply_bad_signature`       | tampered-signature v2 sidecar (PQC verifier surrogate; preflight refused) | rc=1; `... preflight refused`; `signature failed ML-DSA-44 PQC verification`                                                                                | NONE                                                                           |
| `B_R14_reload_apply_corrupted_marker`    | unparseable on-disk pqc_authority_state.json                              | rc=1; `FATAL`/`refused`/`failed to load`/`deserialize`                                                                                                      | NONE — corrupted marker bytes preserved bit-for-bit                            |

For every mutating accepted scenario, the harness asserts:

* lifecycle validation occurs **before** any live trust mutation
  (the Run 134 preflight log line precedes the Run 070 apply line);
* Run 070 apply succeeds (`trust-bundle candidate APPLIED live`);
* Run 055 sequence commit succeeds (`sequence_commit=ok`);
* the v2 authority marker persists strictly **after** sequence commit
  (the Run 134 `v2 authority-marker persisted` line follows the
  Run 070 `APPLIED live` line, and the marker has `record_version=2`
  with the expected `latest_authority_domain_sequence` and
  `latest_lifecycle_action`);
* marker JSON / SHA-256 before and after are captured;
* sequence JSON / SHA-256 after the run is captured;
* live session eviction is observable when applicable (the `Run 134`
  apply path runs through the existing `validate → snapshot → swap →
  evict_sessions → commit_sequence` pipeline, evidenced by the
  `VERDICT=applied` marker which `apply_post_validation` emits only
  after the full four-step pipeline completes — see Run 112 / Run 070).

For every rejected scenario (validation-only or mutating), the harness
asserts:

* binary exits non-zero;
* lifecycle / marker rejection is visible on stderr (the Run 132
  `VERDICT=invalid`, the Run 134 `FATAL: reload-apply refused by v2
  authority-marker preflight`, or the Run 161 `Run 161: v2 authority-
  marker lifecycle transition rejected by Run 159 validator: ...`
  line, depending on which decision the helper reaches first);
* no live trust swap (no `trust-bundle candidate APPLIED live`);
* no session eviction (no `session_evictions=N≥1`);
* no Run 055 sequence write (no `pqc_trust_bundle_sequence.json` under
  the scenario data dir);
* no v2 marker write (no `pqc_authority_state.json` created when none
  was seeded; pre-seeded marker bytes preserved when one was);
* no `.tmp` residue;
* no `falling back to --p2p-trusted-root`;
* no `active DummySig` / `active DummyKem` / `active DummyAead`.

## Reachability proof — Run 160 boundary explicitly superseded

The harness writes `reachability/src_grep.txt` and
`reachability/reachability.txt` capturing a `grep -nE
'validate_v2_lifecycle_transition|LifecycleRejected'` over
`crates/qbind-node/src/**.rs`. The hits are asserted to include:

```
crates/qbind-node/src/pqc_authority_marker_acceptance.rs:... validate_v2_lifecycle_transition ...
crates/qbind-node/src/pqc_authority_marker_acceptance.rs:... LifecycleRejected ...
```

These are **production callers** in the same module the release
binary's `decide_marker_acceptance_v2` lives in (the helper invoked by
`main.rs` reload-apply, `pqc_live_trust_reload.rs` SIGHUP, and
`pqc_peer_candidate_apply.rs` peer-driven drain — see Run 161 source
delta). Run 160 recorded zero such callers in its
`call_graph/reachability.txt`; Run 162 explicitly supersedes that
boundary.

## Required captured metadata

`provenance.txt` records:

* git commit hash;
* `rustc` / `cargo` versions;
* `qbind-node` SHA-256 and ELF Build ID;
* `run_133_v2_validation_only_fixture_helper` SHA-256 and ELF Build ID;
* `run_160_authority_lifecycle_fixture_helper` SHA-256 and ELF Build
  ID;
* the exact `OUTDIR` and repo root the harness ran in.

`fixture_manifest.txt` records the SHA-256 of every minted fixture
file. `marker_hashes/`, `sequence_hashes/`, `data_inventories/`,
`exit_codes/`, `logs/` and `grep_summaries/` carry the per-scenario
captures listed above.

## Validation commands

The task's required validation commands are run on the same checkout
and captured by the operator running:

* `cargo build --release -p qbind-node --bin qbind-node`
* `cargo build --release -p qbind-node --example run_160_authority_lifecycle_fixture_helper`
* `cargo build --release -p qbind-node --example run_133_v2_validation_only_fixture_helper`
* `bash scripts/devnet/run_162_authority_lifecycle_release_binary_enforcement.sh`
* `cargo test -p qbind-node --test run_161_lifecycle_marker_integration_tests`
* `cargo test -p qbind-node --test run_159_authority_signing_key_lifecycle_tests`
* `cargo test -p qbind-node --test run_157_unified_testnet_fixture_universe_tests`
* `cargo test -p qbind-node --test run_152_binary_reachable_peer_drain_plumbing_tests`
* `cargo test -p qbind-node --test run_150_peer_driven_apply_drain_tests`
* `cargo test -p qbind-node --test run_148_peer_driven_apply_devnet_tests`
* `cargo test -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests`
* `cargo test -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests`
* `cargo test -p qbind-node --test run_138_sighup_v2_authority_marker_tests`
* `cargo test -p qbind-node --lib pqc_authority`
* `cargo test -p qbind-node --lib`

## Required denylist (the harness's `out_of_scope.txt` must be empty)

* no autonomous drain;
* no apply on receipt;
* no peer-majority authority;
* no governance enforced;
* no KMS / HSM enforced;
* no validator-set rotated;
* no MainNet apply enabled;
* no fallback to `--p2p-trusted-root`;
* no active `DummySig` / `DummyKem` / `DummyAead`;
* no schema/wire/metric drift;
* no claim of full **C4** / **C5** closure.

The standard MainNet-refusal banner — which names `governance` /
`KMS` / `HSM` / `signing-key rotation/revocation` only to say they are
NOT implemented — is excluded from the denylist match (same precedent
as Run 153 / 155 / 156 / 158 / 160).

## Invariants held in this run

* MainNet remains refused (no harness scenario enables MainNet
  drain-once or MainNet apply).
* No autonomous background drain.
* No automatic apply on receipt.
* No peer-majority authority.
* No fallback to `--p2p-trusted-root`.
* No active `DummySig` / `DummyKem` / `DummyAead`.
* No SIGHUP / startup-trust-bundle / live `0x05` / drain-once code path
  is touched by Run 162.
* No marker write before sequence commit on any accept scenario.
* No sequence write on any reject scenario.
* No marker write on any reject scenario.
* DevNet evidence from Run 153, TestNet evidence from Runs 154 / 155 /
  156 / 157 / 158, and Run 160's release-binary lifecycle-fixture
  boundary remain valid and untouched (Run 160 is now historically
  superseded by Run 162 only with respect to the call-site
  reachability claim).

## Out-of-scope deferrals (unchanged)

* Governance / KMS / HSM: unimplemented.
* Validator-set rotation: open.
* Full **C4**: open. **C5**: open.
* MainNet: refused unconditionally.

## Tracked vs generated artifacts

Only `README.md` and `summary.txt` are tracked (mirroring Run 153 /
Run 155 / Run 156 / Run 158 / Run 160). All per-run artifacts (`logs/`,
`data/`, `exit_codes/`, `grep_summaries/`, `fixtures/`, `marker_hashes/`,
`sequence_hashes/`, `data_inventories/`, `reachability/`,
`provenance.txt`, `fixture_manifest.txt`) are reproduced by the
harness and are `.gitignore`d (they contain absolute paths, ephemeral
helper output, and timestamps).

See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_162.md` for the canonical
evidence report.
