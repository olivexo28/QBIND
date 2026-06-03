# QBIND DevNet Evidence — Run 175

## Scope

Run 175 is **release-binary local peer-candidate-check Required-policy
governance-proof evidence**.

It proves on real `target/release/qbind-node` that the local
`--p2p-trust-bundle-peer-candidate-check` validation-only v2
marker-decision production surface (Run 077 / Run 107 envelope path
→ Run 132 preflight) enforces
`GovernanceProofPolicy::RequiredForLifecycleSensitive` via the hidden
Run 171 selector (`--p2p-trust-bundle-governance-proof-required` /
`QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED=1`, truthy
`1|true|yes|on`) using the Run 173 validation-only wiring:

* default local peer-candidate-check behaviour remains `NotRequired`;
* the CLI selector activates `RequiredForLifecycleSensitive` on the
  local peer-candidate-check production surface;
* the env selector activates `RequiredForLifecycleSensitive` on the
  local peer-candidate-check production surface;
* under Required policy, valid proof-carrying GenesisBound `Rotate`
  sidecars pass anti-rollback / lifecycle / governance checks on the
  local peer-candidate-check production surface and the surface logs
  `[run-132] peer-candidate-check v2 authority-marker check passed ...
  governance policy=RequiredForLifecycleSensitive`;
* under Required policy, no-proof / malformed / invalid-signature /
  wrong-root / wrong-action / wrong-digest / wrong-sequence /
  unsupported-suite / `OnChainGovernance` proof-carrying sidecars all
  fail closed on the local peer-candidate-check preflight surface
  with `[binary] Run 132: VERDICT=invalid` and exit code 1;
* under Required policy, an idempotent (same-bytes replay)
  proof-carrying Rotate sidecar is accepted and produces no mutation;
* the local peer-candidate-check surface remains strictly
  non-mutating across every scenario (accept and reject): no marker
  write, no sequence write, no Run 070 apply call, no `[run-134]
  reload-apply v2 ratification path SELECTED` line, no `[run-134] v2
  authority-marker persisted` line, no live trust mutation, no
  session eviction, no `.tmp` residue, no fallback to
  `--p2p-trusted-root`, and no active `DummySig` / `DummyKem` /
  `DummyAead`;
* MainNet peer-driven apply remains refused under Run 147 FATAL even
  with `--p2p-trust-bundle-governance-proof-required` +
  `--p2p-trust-bundle-peer-candidate-staging-enabled` + a valid
  proof-carrying Rotate sidecar + a valid local peer-candidate
  envelope;
* the selector cannot be implicitly enabled by unrelated flags (a
  no-proof Rotate sidecar without selector is accepted under default
  `NotRequired`).

Run 175 is the partner deliverable to Run 174 on the
peer-candidate-check side. Run 173 wired BOTH validation-only call
sites at source/test level
(`preflight_run_132_validation_only_v2_marker_check` resolves the
active policy via
`qbind_node::pqc_governance_proof_surface::governance_proof_policy_from_cli_or_env(ctx_data.governance_proof_required_selector)`
and routes through the Run 173 surface shim
`qbind_node::pqc_governance_proof_surface::preflight_v2_validation_only_marker_check_with_governance_proof_load`,
which delegates to the existing Run 169 mutating shim
`preflight_v2_marker_decision_with_governance_proof_load` — there is
**no second selector path and no second gate path**); Run 174
captured the release-binary evidence for the
`--p2p-trust-bundle-reload-check` validation-only call site; Run 175
captures the release-binary evidence for the local
`--p2p-trust-bundle-peer-candidate-check` validation-only call site
and closes the Run 174-deferred peer-candidate-check release-binary
cases (A4 / A5 / R15 / R16 in Run 174 numbering).

Default remains `NotRequired`. Hidden CLI/env selector activates
Required policy on the local peer-candidate-check surface. Existing
no-proof candidates remain compatible under `NotRequired`. Required
policy fails closed when proof is absent. Valid proof-carrying
candidates pass under Required policy through the real local
peer-candidate-check production surface where lifecycle /
anti-rollback checks pass. Invalid proof-carrying candidates fail
closed. Local peer-candidate-check remains strictly non-mutating.
**Live inbound `0x05` proof-carrying remains OPEN** because the
on-the-wire peer-candidate envelope schema does not yet carry the
`governance_authority_proof` sibling; lifting live `0x05` to Required
policy would require an envelope schema change, which is explicitly
forbidden by `task/RUN_175_TASK.txt`. `OnChainGovernance` remains
unsupported / fail-closed at the Run 163 verifier on every surface,
including the local peer-candidate-check validation-only surface.
**No MainNet apply is enabled.** Governance execution / on-chain
proof remains unimplemented. KMS/HSM remains unimplemented.
Validator-set rotation remains open. Full C4 remains open unless
separately closed by explicit criteria. C5 remains open.

## Verdict

**PASS** — release-binary local peer-candidate-check Required-policy
production-surface evidence captured. Per-scenario verdicts and exit
codes are recorded in
`docs/devnet/run_175_peer_candidate_check_governance_required_policy_release_binary/summary.txt`,
and the harness writes per-scenario stdout / stderr logs, marker /
sequence SHA-256 before/after, exit-code files, data-dir inventories,
fixture manifest, source-reachability greps, denylist greps, and
cargo-test logs under
`docs/devnet/run_175_peer_candidate_check_governance_required_policy_release_binary/`
(all of which are `.gitignored` — only `README.md`, `summary.txt`,
and `.gitignore` are tracked, per the
Run 153/155/156/158/160/162/164/166/168/170/172/174 precedent).

## Honest limitations (preserved, NOT a Run 175 closure)

1. **Live inbound `0x05` proof-carrying remains OPEN.** The on-the-
   wire peer-candidate envelope schema
   (`crates/qbind-node/src/pqc_peer_candidate_wire.rs`) does **not**
   carry a `governance_authority_proof` sibling, so the live `0x05`
   validation surface (`verify_marker_for_validation_only_v2`) cannot
   yet supply a typed `GovernanceProofLoadStatus` to the Run 173
   shim. Run 175 covers only the LOCAL
   `--p2p-trust-bundle-peer-candidate-check` binary surface (Run 077
   / Run 107), where the proof-carrying ratification is supplied
   separately via the existing `--p2p-trust-bundle-ratification`
   argument and parsed by the production loader
   `load_versioned_ratification_with_governance_proof_from_path`. The
   live `0x05` envelope schema change is explicitly forbidden by
   `task/RUN_175_TASK.txt`; this boundary is documented and deferred
   without weakening any prior invariant.

2. **`R5` (wrong-environment), `R6` (wrong-chain), `R7`
   (wrong-genesis) proof-carrying Rotate sidecars** cannot be
   expressed as bit-for-bit static fixtures consumable by the binary
   without changing the production environment / chain / genesis the
   binary is invoked with (which would itself trip the Run 130 v2
   ratification verifier upstream of the governance gate, masking
   the governance-gate refusal that Run 175 is trying to evidence).
   These three scenarios are covered at source level by the Run 173
   source-test integration suite (R5–R7) and at symbol level by the
   Run 168 release-built helper
   (`run_168_governance_proof_carrier_release_binary_helper`). This
   deferral pattern mirrors Run 174 / Run 172 precedent.

3. **`R13` (local operator config alone) and `R14` (peer-majority
   alone)** are covered by construction: the Run 173 validation-only
   shim has **no** operator-config carrier and **no** peer-majority
   carrier — operator config alone and peer-majority alone CANNOT
   stand in for a governance proof. Under Required policy, any
   no-proof Rotate sidecar (regardless of any operator config or
   peer-majority context) is rejected with
   `GovernanceAuthorityRequiredButMissing`, mirrored by R1 / R2.

## Acceptance matrix (release binary)

| ID  | Surface                          | Selector            | Sidecar                          | Outcome |
| --- | -------------------------------- | ------------------- | -------------------------------- | ------- |
| A1  | local peer-candidate-check       | default (none)      | no-proof Ratify@seq=1            | ✅ accepted; `governance policy=NotRequired`; no marker / no sequence write |
| A2  | local peer-candidate-check       | CLI Required        | proof-carrying Rotate@seq=2      | ✅ accepted; `[run-132] peer-candidate-check v2 authority-marker check passed`; `governance policy=RequiredForLifecycleSensitive`; no writes |
| A3  | local peer-candidate-check       | env Required (`=1`) | proof-carrying Rotate@seq=2      | ✅ accepted; same as A2 via env selector |
| A4a | local peer-candidate-check       | env=`false`         | no-proof Rotate@seq=2            | ✅ accepted; `governance policy=NotRequired` |
| A4b | local peer-candidate-check       | env=`0`             | no-proof Rotate@seq=2            | ✅ accepted; `governance policy=NotRequired` |
| A5  | local peer-candidate-check       | CLI Required        | idempotent (same-bytes) Rotate@seq=2 | ✅ accepted; `governance policy=RequiredForLifecycleSensitive`; no mutation |

## Rejection matrix (release binary)

| ID    | Selector  | Proof Status                                              | Surface                    | Expected Outcome |
| ----- | --------- | --------------------------------------------------------- | -------------------------- | -- |
| R1    | CLI Req   | Absent (no proof) on Rotate                               | local peer-candidate-check | rc=1; `requires a governance authority proof` (`GovernanceAuthorityRequiredButMissing { action: Rotate }`); no mutation |
| R2    | env Req   | Absent (no proof) on Rotate                               | local peer-candidate-check | rc=1; same as R1 via env selector |
| R3    | Req       | Malformed proof JSON                                      | local peer-candidate-check | rc=1; `[binary] Run 132: VERDICT=invalid`; no mutation |
| R4    | Req       | Available, invalid issuer signature                       | local peer-candidate-check | rc=1; `GovernanceAuthorityRejected(InvalidIssuerSignature)`; no mutation |
| R5    | Req       | Available, wrong environment                              | local peer-candidate-check | deferred-source-test (Run 130 trips upstream; covered by Run 173 source-test + Run 168 helper) |
| R6    | Req       | Available, wrong chain                                    | local peer-candidate-check | deferred-source-test (same rationale as R5) |
| R7    | Req       | Available, wrong genesis                                  | local peer-candidate-check | deferred-source-test (same rationale as R5) |
| R8    | Req       | Available, wrong authority root                           | local peer-candidate-check | rc=1; `GovernanceAuthorityRejected(...)`; no mutation |
| R9    | Req       | Available, wrong lifecycle action                         | local peer-candidate-check | rc=1; `GovernanceAuthorityRejected(...)`; no mutation |
| R10   | Req       | Available, wrong candidate digest                         | local peer-candidate-check | rc=1; `GovernanceAuthorityRejected(...)`; no mutation |
| R11   | Req       | Available, wrong authority-domain sequence                | local peer-candidate-check | rc=1; `GovernanceAuthorityRejected(...)`; no mutation |
| R12   | Req       | Available, OnChainGovernance class                        | local peer-candidate-check | rc=1; `GovernanceAuthorityRejected(UnsupportedOnChainGovernance)`; no mutation |
| R13   | Req       | Local operator config alone                               | local peer-candidate-check | covered by R1: shim has no operator-config carrier; Absent ⇒ `RequiredButMissing` |
| R14   | Req       | Peer-majority alone                                       | local peer-candidate-check | covered by R1: shim has no peer-majority carrier; Absent ⇒ `RequiredButMissing` |
| R-extra | Req     | Available, unsupported issuer suite                       | local peer-candidate-check | rc=1; `GovernanceAuthorityRejected(...)`; no mutation |
| R15   | Req       | (any reject)                                              | local peer-candidate-check | no marker write; no sequence write (asserted per case via `assert_no_mutation`) |
| R16   | Req       | (any reject)                                              | local peer-candidate-check | no Run 070 apply; no live trust swap; no session eviction; no `[run-134]` mutating apply path SELECTED line |
| R17   | (none)    | (any)                                                     | local peer-candidate-check | rc=0; selector cannot be implicitly enabled by unrelated flags; default `NotRequired` |
| R18   | CLI Req   | Available, valid proof on Rotate                          | MainNet peer-driven        | rc=1; Run 147 FATAL `peer-candidate-staging refused on MainNet`; no Run 070 apply, no marker persist |

## Selector proof

* **CLI hidden flag.** `qbind-node --help` does NOT mention
  `--p2p-trust-bundle-governance-proof-required` (clap `hide = true`
  declared in `crates/qbind-node/src/cli.rs`), and does NOT mention
  `--p2p-trust-bundle-peer-candidate-check` (clap `hide = true` on
  the same module). When the selector is passed explicitly on the
  command line, it is parsed and observed in
  `Run105ReloadCheckContextData::governance_proof_required_selector`
  at preflight time (the same struct that drives the
  `--p2p-trust-bundle-ratification` v2 dispatch for both the
  reload-check and peer-candidate-check binary paths).
* **Env var.** `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED=1`,
  `=true`, `=yes`, `=on` (case-insensitive) all enable the selector
  through `governance_proof_required_env_selector_enabled`. Any
  other value (empty, `0`, `false`, unrecognized) leaves the
  selector disabled and the policy on its `NotRequired` default.
  Verified at release binary level by A2 / A3 (truthy values) and
  A4a / A4b (`false` / `0` preserves `NotRequired`).
* **Source-reachability greps** (captured under
  `reachability/source_reachability.txt`):

  * `governance_proof_policy_from_cli_or_env` — defined in
    `crates/qbind-node/src/pqc_governance_proof_surface.rs`; called
    from `crates/qbind-node/src/main.rs` at the validation-only
    reload-check site, the local validation-only peer-candidate-check
    site (both routed through
    `preflight_run_132_validation_only_v2_marker_check`), the
    mutating reload-apply preflight, the startup
    `--p2p-trust-bundle` preflight, the SIGHUP live-reload preflight
    (in `pqc_live_trust_reload.rs`), and the peer-driven
    `ProductionV2MarkerCoordinator` (in `pqc_peer_candidate_apply.rs`).
  * `preflight_run_132_validation_only_v2_marker_check` — defined in
    `crates/qbind-node/src/main.rs`; called from BOTH the validation-
    only `--p2p-trust-bundle-reload-check` path AND the local
    `--p2p-trust-bundle-peer-candidate-check` path; Run 175 evidences
    the latter at release-binary level for the first time.
  * `preflight_v2_validation_only_marker_check_with_governance_proof_load`
    — Run 173 surface shim defined in
    `crates/qbind-node/src/pqc_governance_proof_surface.rs`;
    delegates to `preflight_v2_marker_decision_with_governance_proof_load`
    (the Run 169 shim).
  * `preflight_v2_marker_decision_with_governance_proof_load` —
    Run 169 shim defined in
    `crates/qbind-node/src/pqc_governance_proof_surface.rs`; the
    single integration shim for both validation-only and mutating
    callers.
  * `load_versioned_ratification_with_governance_proof_from_path` —
    Run 167 / Run 169 dispatcher referenced from `main.rs`,
    `pqc_live_trust_reload.rs`, and the peer-driven coordinator;
    composed into the local peer-candidate-check binary path via
    `build_run_105_reload_check_context` (which is shared by the
    reload-check and local peer-candidate-check binary surfaces).
  * `GovernanceProofContext::Available` — reached on every accept
    case where the proof sibling is well-formed and binds correctly.
  * `p2p_trust_bundle_peer_candidate_check` — CLI struct field in
    `crates/qbind-node/src/cli.rs`; the binary entrypoint guarded by
    `pqc_peer_candidate_binary::run077_hook_active` consumes it via
    `args.p2p_trust_bundle_peer_candidate_check.as_deref()` in
    `crates/qbind-node/src/main.rs`.

## Production-surface reachability proof

The harness captures release-binary stderr lines proving the local
peer-candidate-check validation-only production surface is exercised:

* **Required policy active (A2 / A3):** `[run-132] peer-candidate-
  check v2 authority-marker check passed: v2-upgrade 1 -> 2
  (validation-only; no marker persistence; no trust mutation;
  governance policy=RequiredForLifecycleSensitive)`.
* **Proof-carrying Available path (A2 / A3 / A5):** `Run 077:
  VERDICT=validated` on a candidate carrying a well-formed
  proof-carrying ratification sidecar.
* **Proof-required missing path (R1 / R2):** `[binary] Run 132:
  VERDICT=invalid (peer-candidate-check v2 authority-marker
  conflict; ...)` with the typed
  `Run 165: v2 authority-marker decision requires a governance
  authority proof for lifecycle action 'rotate' but none was
  available`.
* **Invalid / malformed proof path (R3 / R4 / R8–R12 / R-extra):**
  `[binary] Run 132: VERDICT=invalid` with the typed
  `Run 165: v2 authority-marker governance authority proof rejected
  by Run 163 verifier: ...` for each rejection case.
* **No-mutation behavior:** `assert_no_mutation` is invoked on every
  validation-only scenario (accept and reject) and verifies marker
  SHA pre==post (if seeded), `pqc_trust_bundle_sequence.json` absent
  post-run, no `Run 070: trust-bundle candidate APPLIED` line, no
  `[run-134] reload-apply v2 ratification path SELECTED` line, and
  no `[run-134] v2 authority-marker persisted` line. The
  `consensus/` RocksDB sub-dir and the
  `run077-peer-candidate-scratch/` directory in the per-scenario
  data-dir are expected and benign (Run 098 ConsensusStorage open
  for activation epoch read + Run 077 scratch tempfile parent) and
  do NOT constitute marker or sequence persistence.

## No-mutation proof

For every validation-only scenario in this run:

* no Run 070 apply call (`Run 070: trust-bundle candidate APPLIED`
  absent on stderr);
* no live trust swap (`pqc_trust_bundle_sequence.json` absent in the
  scenario data-dir; `assert_no_mutation` enforces);
* no session eviction (no peer-session telemetry line; the
  validation-only surfaces never reach the eviction code path);
* no sequence write (`pqc_trust_bundle_sequence.json` absent post-
  run; `assert_no_mutation` enforces);
* no marker write (`pqc_authority_state.json` byte-for-byte
  unchanged if seeded; absent if not seeded; `assert_no_mutation`
  enforces);
* marker bytes unchanged if present (SHA-256 pre == post via
  `cmp -s`);
* sequence bytes unchanged if present (file MUST NOT exist post-
  run; enforced by `assert_no_mutation`);
* no `.tmp` residue under `pqc_authority_state.json` /
  `pqc_trust_bundle_sequence.json` (per-scenario data-dir
  inventories under `data_inventories/`);
* no fallback to `--p2p-trusted-root` (denylist grep);
* no active `DummySig` / `DummyKem` / `DummyAead` (denylist grep).

## Denylist proof

Across the run:

* no MainNet apply (denylist grep);
* no autonomous apply (denylist grep);
* no apply on receipt (denylist grep);
* no peer-majority authority (denylist grep);
* no governance execution claim;
* no on-chain governance claim (`OnChainGovernance` remains
  unsupported / fail-closed at Run 163 verifier; R12 evidences this
  on the local peer-candidate-check validation-only surface);
* no KMS/HSM claim;
* no validator-set rotation claim;
* no fallback to `--p2p-trusted-root` (denylist grep);
* no active `DummySig` / `DummyKem` / `DummyAead` (denylist grep);
* no schema / wire / metric drift (no source change to wire
  formats, marker schema, sequence-file schema, trust-bundle
  schema, peer-candidate-envelope schema, or metric families in
  Run 175);
* no sequence write on validation-only surfaces (every scenario
  asserted via `assert_no_mutation`);
* no marker write on validation-only surfaces (every scenario
  asserted via `assert_no_mutation`).

## Captured metadata

The harness writes (under
`docs/devnet/run_175_peer_candidate_check_governance_required_policy_release_binary/`,
all `.gitignored` per the
Run 153/155/156/158/160/162/164/166/168/170/172/174 precedent):

* `provenance.txt` — `qbind-node` SHA-256 + ELF Build ID, Run 175
  helper SHA-256 + ELF Build ID, git commit hash, rustc / cargo
  versions, date.
* `fixture_manifest.txt` — fixture file paths, sizes, SHA-256 (for
  every minted ratification sidecar AND every minted local
  PeerCandidateEnvelope JSON).
* `logs/<scenario>.{stdout,stderr}.log` — per-scenario stdout /
  stderr.
* `exit_codes/<scenario>.exit_code` — per-scenario exit code.
* `marker_hashes/<scenario>.{marker_pre,marker_post}.sha256` —
  marker SHA-256 before / after each scenario.
* `sequence_hashes/<scenario>.{sequence_pre,sequence_post}.sha256`
  — sequence SHA-256 before / after each scenario (post must be
  empty on every validation-only scenario).
* `data_inventories/<scenario>.inventory.txt` — per-scenario data-
  dir file listing.
* `reachability/source_reachability.txt` — source-reachability
  greps.
* `grep_summaries/{cli_hidden,denylist}.txt` — CLI hidden flag
  proof and denylist scans.
* `test_results/<test>.{stdout,stderr}.log` — `cargo test --release`
  output for the cross-checked test suites.
* `scenario_assertions.txt` — machine-grep-friendly per-scenario
  assertion summary.
* `negative_invariants.txt` — negative invariants enforced by the
  harness.

The committed `summary.txt` contains the per-scenario rc table and
the verdict summary; the committed `README.md` documents the
directory layout, scope, honest limitations, and inheritance.

## Validation commands

```text
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node --example run_175_peer_candidate_check_governance_required_policy_release_binary_helper
bash scripts/devnet/run_175_peer_candidate_check_governance_required_policy_release_binary.sh
cargo test  -p qbind-node --release --test run_173_validation_only_governance_required_policy_tests
cargo test  -p qbind-node --release --test run_171_governance_required_policy_selector_tests
cargo test  -p qbind-node --release --test run_169_governance_proof_loader_surface_integration_tests
cargo test  -p qbind-node --release --test run_167_governance_proof_carrier_tests
cargo test  -p qbind-node --release --test run_165_governance_marker_integration_tests
cargo test  -p qbind-node --release --test run_163_governance_authority_verifier_tests
cargo test  -p qbind-node --release --test run_161_lifecycle_marker_integration_tests
cargo test  -p qbind-node --release --test run_159_authority_signing_key_lifecycle_tests
cargo test  -p qbind-node --release --test run_157_unified_testnet_fixture_universe_tests
cargo test  -p qbind-node --release --test run_152_binary_reachable_peer_drain_plumbing_tests
cargo test  -p qbind-node --release --test run_150_peer_driven_apply_drain_tests
cargo test  -p qbind-node --release --test run_148_peer_driven_apply_devnet_tests
cargo test  -p qbind-node --release --test run_142_live_inbound_0x05_v2_validation_tests
cargo test  -p qbind-node --release --test run_134_reload_apply_v2_authority_marker_tests
cargo test  -p qbind-node --release --test run_138_sighup_v2_authority_marker_tests
cargo test  -p qbind-node --release --lib pqc_authority
cargo test  -p qbind-node --release --lib
```

The harness invokes the first three lines (build + harness) and the
release cargo test suite for the six closest-related governance
suites (Run 173, Run 171, Run 169, Run 167, Run 165,
`--lib pqc_authority`) inline; the remaining suites are listed for
cross-check completeness and were verified by Run 173 / Run 174
closure.

## Acceptance criteria (verbatim from `task/RUN_175_TASK.txt`)

1. ✅ Real release binaries exercise Required policy on local
   peer-candidate-check (A2 / A3 / A5).
2. ✅ Default `NotRequired` compatibility remains proven (A1 / A4a /
   A4b / R17).
3. ✅ CLI selector and env selector both activate Required policy
   for local peer-candidate-check (A2 / A3 + R1 / R2).
4. ✅ Required / no-proof local peer-candidate-check cases fail
   closed (R1 / R2).
5. ✅ Valid proof-carrying candidates reach and pass the governance
   gate on local peer-candidate-check (A2 / A3 / A5 with `[run-132]
   peer-candidate-check v2 authority-marker check passed ...
   governance policy=RequiredForLifecycleSensitive`).
6. ✅ Invalid proof-carrying candidates fail closed (R3 / R4 / R8 /
   R9 / R10 / R11 / R12 / R-extra).
7. ✅ Local peer-candidate-check scenarios produce no mutation
   (`assert_no_mutation` asserted per case for every accept and
   reject; R15 / R16).
8. ✅ MainNet remains refused even with Required policy and valid
   governance proof (R18).
9. ✅ No governance execution / KMS-HSM / validator-set rotation
   claim is made.
10. ✅ No full C4 or C5 closure is claimed.

## Standing invariants (unchanged)

* MainNet peer-driven apply remains refused (Run 147 FATAL
  preserved).
* `OnChainGovernance` remains unsupported / fail-closed at the
  Run 163 verifier on every surface, including the local peer-
  candidate-check validation-only surface.
* Governance execution remains unimplemented.
* On-chain governance remains unimplemented.
* KMS/HSM remains unimplemented.
* Validator-set rotation remains open.
* No new wire / marker / sequence-file / trust-bundle / peer-
  candidate-envelope / governance-proof-wire schema change.
* No new CLI flag, no new env var (the Run 171 selector and the
  Run 077 `--p2p-trust-bundle-peer-candidate-check` flag are both
  unchanged).
* No new metric family.
* No production source change in Run 175 (release-binary evidence
  / harness / docs / fixture-tooling helper only).
* Live inbound `0x05` proof-carrying remains OPEN.
* Full C4 remains open.
* C5 remains open.

## Crosscheck against existing design / spec

Run 175 was crosschecked against the Run 077 / 105 / 107 / 130 /
131 / 132 / 134 / 138 / 142 / 148 / 150 / 152 / 159 / 161 / 163 /
165 / 167 / 169 / 171 / 172 / 173 / 174 design and spec documents.
**No contradiction or inconsistency was discovered.** Specifically:

* Run 077 / Run 107 partial-config refusal discipline and
  validation-only invariants are unchanged; Run 175 only consumes
  the existing `--p2p-trust-bundle-peer-candidate-check` envelope
  argument and the existing `--p2p-trust-bundle-ratification`
  argument (which already supports v2 + governance-proof sibling
  via the Run 167 / Run 169 loader since Run 174).
* Run 105 reload-check context construction (`build_run_105_reload_check_context`)
  is shared by both the validation-only `--p2p-trust-bundle-reload-check`
  binary path and the local
  `--p2p-trust-bundle-peer-candidate-check` binary path; the Run
  171 selector capture (`governance_proof_required_selector`) and
  the Run 169 loader call
  (`load_versioned_ratification_with_governance_proof_from_path`)
  apply identically to both call sites.
* Run 130 environment policy still owns the MainNet refusal at the
  upstream binary gate; Run 175 evidences this on the local
  peer-candidate-check binary path via R18 (Run 147 FATAL on
  `--p2p-trust-bundle-peer-candidate-staging-enabled` on MainNet).
* Run 132 v2-sidecar dispatch in `main.rs` for the local peer-
  candidate-check path is unchanged; Run 173's switch to the
  validation-only shim only replaces the inner verifier call with
  `preflight_v2_validation_only_marker_check_with_governance_proof_load`,
  which composes the same anti-rollback / lifecycle / governance
  gate the Run 165 / 169 / 171 production helper composes on the
  mutating surfaces. Both validation-only call sites
  (`--p2p-trust-bundle-reload-check` + local peer-candidate-check)
  consume the same shim by construction.
* Run 144 peer-driven apply safety contract is unchanged; Run 175
  does not exercise the peer-driven apply surface beyond R18's
  MainNet refusal proof.
* Run 165 governance gate is the **only** governance gate in the
  source tree; Run 175 reaches it from the local peer-candidate-
  check validation-only surface via the Run 173 shim, and there is
  no second gate path.
* Run 167 carrier wire schema is unchanged; Run 175 does not
  introduce any new wire field, new sidecar field, or any schema
  drift.
* Run 171 selector helpers are unchanged; Run 175 only exercises
  them through the local peer-candidate-check validation-only
  surface (A2 / A3 / A5 + R1 / R2 + R8..R12 / R-extra) and via the
  no-selector default (A1 / A4a / A4b / R17).
* Run 172 mutating-surface evidence is unchanged and remains
  valid; Run 175 is a partner-evidence run for the validation-only
  peer-candidate-check side and does not weaken the mutating-
  surface evidence.
* Run 173 source-test integration is unchanged; Run 175 re-runs
  the Run 173 suite as a cross-check (`cargo test --release ...`)
  inside the harness.
* Run 174 reload-check release-binary evidence is unchanged;
  Run 175 closes the Run 174-deferred peer-candidate-check
  release-binary cases (A4 / A5 / R15 / R16 in Run 174 numbering)
  without weakening any Run 174 invariant.
* The Run 175 helper introduces only a NEW release-built example
  target (`run_175_peer_candidate_check_governance_required_policy_release_binary_helper`)
  that produces the same Run 172-shape ratification corpus PLUS
  Run 076-schema PeerCandidateEnvelope JSONs wrapping the existing
  candidate trust bundles. The envelope schema, the bundle schema,
  and the v2 ratification schema are all unchanged.

`docs/whitepaper/contradiction.md` records this crosscheck under
the Run 175 paragraph.