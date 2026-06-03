# Run 183 — Release-binary OnChainGovernance production call-site evidence

## Scope

Closes the Run 182-deferred release-binary boundary for the source/test
production call-site wiring of the Run 180 per-surface
`OnChainGovernance` preflight wrappers. Run 182 added the new library
module
[`crates/qbind-node/src/pqc_onchain_governance_callsite_wiring.rs`](
  ../../../crates/qbind-node/src/pqc_onchain_governance_callsite_wiring.rs)
exposing seven named **production call-site entries**
(`reload_check_callsite_` / `reload_apply_callsite_` /
`startup_p2p_trust_bundle_callsite_` / `sighup_callsite_` /
`local_peer_candidate_check_callsite_` /
`live_inbound_0x05_callsite_` /
`peer_driven_drain_callsite_onchain_governance_marker_decision`) plus
the typed argument bundle `OnChainGovernanceCallsiteContext`, and
wired each entry into its actual production v2 marker-decision code
path:

* `--p2p-trust-bundle-reload-check` → `crates/qbind-node/src/main.rs::preflight_run_132_validation_only_v2_marker_check`;
* `--p2p-trust-bundle-reload-apply-*` → `main.rs::preflight_run_134_v2_marker_decision`;
* startup `--p2p-trust-bundle` → `main.rs::preflight_run_136_v2_marker_decision_for_startup`;
* SIGHUP live trust-bundle reload → `crates/qbind-node/src/pqc_live_trust_reload.rs::LiveReloadController::preflight_sighup_v2_marker_decision`;
* local `--p2p-trust-bundle-peer-candidate-check` → v2 sidecar dispatch in `main.rs`;
* live inbound `0x05` → `crates/qbind-node/src/pqc_peer_candidate_wire.rs` (post `verify_marker_for_validation_only_v2`);
* Run 150 peer-driven apply drain → `crates/qbind-node/src/pqc_peer_candidate_apply.rs::ProductionV2MarkerCoordinator::decide_pre_apply` (with the additive `with_onchain_governance_fixture_allowed_selector` builder).

Each call site captures the hidden Run 180 fixture-allowed selector
(`--p2p-trust-bundle-onchain-governance-fixture-allowed` /
`QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED`) and
invokes the matching Run 182 callsite entry. The peer-driven-drain
entry layers a surface-level `MainNetRefused` short-circuit **before**
invoking the underlying Run 180 verifier so the Run 147 / 148 / 152
FATAL invariant continues to hold even with a fully-valid DevNet
fixture proof in hand and the selector engaged. The wiring is purely
additive: zero schema bumps, zero new wire fields, zero new sidecar
fields, zero new metrics, zero new exit codes. The production default
remains `OnChainGovernanceProofPolicy::Disabled` on every surface.
Run 182 is source/test only.

Run 183 captures **release-binary production call-site reachability**
evidence:

* the real `target/release/qbind-node` binary parses the hidden
  `--p2p-trust-bundle-onchain-governance-fixture-allowed` CLI flag,
  reads the
  `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED`
  environment variable, OR-combines them via
  [`onchain_governance_proof_policy_from_cli_or_env`](
    ../../../crates/qbind-node/src/pqc_onchain_governance_proof_surface.rs)
  inside `crates/qbind-node/src/main.rs`, propagates the resolved
  selector through `Run105ReloadCheckContextData`,
  `LiveReloadConfig`, and `ProductionV2MarkerCoordinator` into every
  Run 182 named callsite entry, and emits the
  `[run-180] hidden DevNet/TestNet OnChainGovernance fixture-proof
  policy ARMED (AllowFixtureSourceTest)` banner exactly when armed;
* the production default — neither flag nor env var truthy — emits
  no banner, preserves the `OnChainGovernanceProofPolicy::Disabled`
  production default on every surface, and every Run 182 callsite
  entry short-circuits on `PolicyDisabled`;
* `qbind-node --help` does not surface the hidden selector flag
  (`hide = true`) and does not surface a `run-180` / `run-181` /
  `run-182` / `run-183` / `onchain-governance-fixture` token;
* the real binary's MainNet peer-driven apply refusal (Run 147 FATAL
  invariant) is unchanged with the selector armed: requesting
  `--print-genesis-hash --network mainnet` with the selector engaged
  emits no `MainNet peer-driven apply ENABLED` token, and the
  peer-driven-drain callsite entry's surface-level `MainNetRefused`
  short-circuit fires ahead of the Run 180 verifier;
* a release-built helper (the Run 179
  `run_179_onchain_governance_proof_release_binary_helper` example,
  reused here because it drives the production library
  `OnChainGovernance` verifier surface and now also the seven
  Run 182 named callsite entries) exercises the Run 178 / 180 / 182
  acceptance and rejection corpus end-to-end in **release mode**
  through the production library symbols
  `verify_onchain_governance_proof`,
  `validate_lifecycle_with_onchain_governance_proof`,
  `compose_onchain_governance_marker_decision`, the seven Run 180
  per-surface composed wrappers, and the seven Run 182 named
  callsite entries plus `OnChainGovernanceCallsiteContext` and
  `with_onchain_governance_fixture_allowed_selector`;
* a source-reachability proof is recorded showing the
  production-source-tree call sites that now invoke each Run 182
  callsite entry, the Run 180 per-surface wrappers, the Run 178
  typed verifier, and the Run 180 selector helpers — all linked
  into the same `target/release/qbind-node` binary.

## Strict scope (no production-source change)

Per `task/RUN_183_TASK.txt`:

* **Release-binary evidence only.** Run 183 introduces no new
  production module, no new production CLI flag, no new env knob, no
  new schema bump, no new wire shape, no new metric, and no new exit
  code beyond the Run 180 / 182 surface. The only new files
  committed by Run 183 are this evidence archive, the harness shell
  script
  (`scripts/devnet/run_183_onchain_governance_callsite_release_binary.sh`)
  and the canonical evidence report
  (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_183.md`), plus narrow
  append-only paragraphs in
  `docs/whitepaper/contradiction.md`,
  `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`,
  `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`,
  and `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`.
* **No MainNet apply enablement.** The Run 147 FATAL invariant
  ("MainNet peer-driven apply is unsupported and fail-closed")
  survives Run 183 unchanged; the helper R23 / R3b scenarios and the
  release-binary R23 capture both reassert it.
* **No real on-chain verifier / bridge / light-client / KMS-HSM /
  validator-set rotation / autonomous apply / apply-on-receipt /
  peer-majority authority** is introduced.
* **No schema / wire / metric drift** beyond the Run 178 additive
  wire shape (`ONCHAIN_GOVERNANCE_PROOF_WIRE_SCHEMA_VERSION = 1`,
  optional sibling field on `GovernanceAuthorityProofWire`) and the
  Run 180 hidden CLI flag and env var. No new payload field on any
  peer-candidate / SIGHUP-trigger / reload-apply trigger /
  startup-bundle / live `0x05` wire format.
* **No marker / sequence-file / trust-bundle core schema change.**

## What is committed

Only `README.md`, `summary.txt`, and `.gitignore` are tracked. Every
per-run artifact under this directory (`logs/`, `data/`,
`exit_codes/`, `marker_hashes/`, `sequence_hashes/`,
`data_inventories/`, `grep_summaries/`, `reachability/`,
`test_results/`, `fixtures/`, `scenarios/`, `helper_evidence/`,
`helper_corpus/`, `provenance.txt`, `fixture_manifest.txt`,
`scenario_assertions.txt`, `negative_invariants.txt`,
`mutation_proof.txt`, `no_mutation_proof.txt`) contains absolute
paths and ephemeral data and is `.gitignore`d on purpose, matching
the Run 153 / 155 / 158 / 172 / 175 / 177 / 179 / 181 evidence-
archive convention.

## Reproducibility

```bash
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node \
    --example run_179_onchain_governance_proof_release_binary_helper
bash scripts/devnet/run_183_onchain_governance_callsite_release_binary.sh
```

`OUTDIR` defaults to this directory. The harness is **idempotent**:
it wipes `logs/`, `data/`, `exit_codes/`, `helper_evidence/`,
`reachability/`, `test_results/`, `scenarios/`, and `grep_summaries/`
on every invocation and re-mints the helper corpus from the
release-built helper. The `summary.txt` line written at the end of
the harness is the canonical verdict.

## Required production surfaces exercised

Per `task/RUN_183_TASK.txt §Required production surfaces`:

* **A. Validation-only:** `--p2p-trust-bundle-reload-check` (real
  binary banner-armed selector reachability for A2 / A3 / R23; the
  Run 182 `reload_check_callsite_onchain_governance_marker_decision`
  named entry is exercised in release mode through the release-built
  helper across the full Rotate / Revoke / EmergencyRevoke fixture
  corpus and the R1–R26 rejection matrix).
* **B. Mutating:** process-start `--p2p-trust-bundle-reload-apply-path`
  (release-binary banner-armed selector reachability for A2 / A3 /
  R23; the Run 182 `reload_apply_callsite_` named entry is exercised
  in release mode through the release-built helper across the
  accepted Rotate corpus with sequence-before-marker ordering
  preserved at the library layer; canonical commitment bytes
  recorded per scenario in `helper_evidence/`).

Also covered by the harness through the release-built helper:

* local `--p2p-trust-bundle-peer-candidate-check`
  (`local_peer_candidate_check_callsite_` named entry);
* live inbound `0x05`
  (`live_inbound_0x05_callsite_` named entry);
* peer-driven drain
  (`peer_driven_drain_callsite_` named entry, including the
  surface-level `MainNetRefused` layer);
* startup `--p2p-trust-bundle`
  (`startup_p2p_trust_bundle_callsite_` named entry);
* SIGHUP live reload
  (`sighup_callsite_` named entry).

## Scenario corpus

Mirrors `task/RUN_183_TASK.txt` exactly:

* **A1 — default Disabled rejects** OnChainGovernance proof on
  reload-check (no CLI flag, no env var). Real `qbind-node` emits no
  Run 180 banner; selector observed disabled; every Run 182
  callsite entry short-circuits on `PolicyDisabled`.
* **A2 — CLI selector** enables `AllowFixtureSourceTest` on
  reload-check; real `qbind-node` emits the
  `[run-180] ... policy ARMED (AllowFixtureSourceTest)` banner. The
  resolved policy is propagated through every Run 182 named callsite
  entry on every production surface within the same binary process.
* **A3 — env selector** enables `AllowFixtureSourceTest` on
  reload-check across truthy variants `{1, true, TRUE, True, yes,
  YES, on, ON}`; falsey variants `{0, false, FALSE, no, off, "",
  garbage}` keep the selector disabled.
* **A4 — CLI selector + reload-apply**, **A5 — env selector +
  reload-apply** — production-call-site reachability is captured on
  the real binary; the corresponding library-level fixture-proof
  acceptance is captured by the release-built helper through
  `reload_apply_callsite_onchain_governance_marker_decision` with
  canonical commitment bytes recorded for every accepted Rotate
  scenario.
* **A6 — local peer-candidate-check** accepts a valid DevNet/TestNet
  fixture Rotate proof under the fixture selector through
  `local_peer_candidate_check_callsite_onchain_governance_marker_decision`
  (validation-only; no sequence write; no marker write).
* **A7 — live inbound `0x05`** accepts a valid fixture proof under
  the fixture selector through
  `live_inbound_0x05_callsite_onchain_governance_marker_decision`
  (no apply-on-receipt; no marker write; no sequence write).
* **A8 — peer-driven drain** accepts a valid fixture proof in
  preflight on a DevNet candidate through
  `peer_driven_drain_callsite_onchain_governance_marker_decision`,
  while MainNet remains refused through the surface-level
  `MainNetRefused` short-circuit layered ahead of the Run 180
  verifier (Run 147 / 148 / 152 FATAL invariant).
* **A9 — GenesisBound and EmergencyCouncil** proof-carrying
  behavior unchanged — captured via the helper's R24 round-trip and
  A7 sibling tests; those proof modes do not enter the
  OnChainGovernance call-site path.
* **R1–R26** — selector unset / wrong env / wrong chain / wrong
  genesis / wrong authority root / wrong governance domain / wrong
  proposal digest / wrong proposal outcome / wrong lifecycle action /
  wrong candidate digest / wrong authority-domain sequence / expired
  governance proof / replayed governance decision / quorum not met /
  threshold not met / invalid proof bytes / unsupported proof suite /
  malformed proof / local operator config alone / peer-majority alone /
  proof valid but lifecycle invalid / lifecycle valid but proof
  invalid / MainNet peer-driven apply refused with armed selector /
  validation-only rejection non-mutating / mutating preflight
  rejection non-mutating / live-`0x05` invalid candidate
  not-propagated. Captured via the release-built helper through
  every Run 182 named callsite entry, plus the release-binary R23
  MainNet refusal capture.

Per-scenario rc, expected typed outcome, actual typed outcome, and
canonical commitment bytes are written to `helper_evidence/` and
surfaced in `summary.txt` (regenerated each run).

## Honest limitations preserved

* **Verdict is `partial-positive`, not `strongest-positive`.**
  Run 182's wire/schema blocker is unchanged: no current
  peer-candidate, SIGHUP-trigger, reload-apply trigger,
  startup-bundle, or live `0x05` payload format carries a typed
  `OnChainGovernanceProof`. Adding such a field is explicitly
  **out of scope** for Run 183 (no schema bump, no wire field, no
  sidecar field, no metric). Therefore production callers in real
  `target/release/qbind-node` invoke the Run 182 callsite entries
  with `proof: None`; the Run 180 wrapper short-circuits on
  `NoOnChainGovernanceProofSupplied` (or `PolicyDisabled` under the
  default), and call-site behaviour is preserved bit-for-bit. The
  accepted-fixture-proof acceptance path A1–A9 / R1–R26 is
  exercised in release mode through the production library symbols
  by the release-built helper, which is linked into the same
  `qbind-node` library surface. Run 183 captures this honestly via
  `mutation_proof.txt` and identifies the strictly next integration
  run that must add the typed-proof payload field.
* **No real on-chain governance, no execution, no bridge / light
  client / KMS-HSM / validator-set rotation.** Run 183 is fixture-
  only and call-site-reachability-only — exactly as Run 180 / 182
  declared their scope.
* **MainNet peer-driven apply remains refused** under all
  combinations (Run 147 FATAL invariant). R23 captures this on the
  real binary and through the helper, including the peer-driven-
  drain callsite entry's surface-level `MainNetRefused` short-circuit
  layered ahead of the Run 180 verifier.
* **No claim of full C4 / C5 closure.** OnChainGovernance execution,
  governance program integration, and validator-set rotation remain
  out of scope.

## Negative invariants

Captured in `negative_invariants.txt` (regenerated each run).
Highlights:

* No `DummySig` / `DummyKem` / `DummyAead` symbol in any captured
  log.
* No `fallback to --p2p-trusted-root` and no peer-majority authority
  claim.
* No autonomous apply / apply-on-receipt / governance-execution
  language in helper or `qbind-node` output.
* The Run 178 / 180 / 181 / 182 / 183 verifier and selector are not
  surfaced via `qbind-node --help` (no flag named
  `p2p-trust-bundle-onchain-governance-fixture-allowed` or
  `onchain-governance` or `run-180` / `run-181` / `run-182` /
  `run-183` is visible).
* No new schema / wire / metric drift beyond the Run 178 additive
  wire shape and the Run 180 hidden selector.
* No marker write before sequence commit; no sequence write or
  marker write on validation-only surfaces; no `.tmp` residue;
  data dir empty for every release-binary scenario in this run
  (every scenario uses `--print-genesis-hash` which never opens a
  data dir).

## Cross-references

* `task/RUN_183_TASK.txt` — driving spec (acceptance / rejection
  matrix, validation commands, deliverables, honest verdict).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_183.md` — canonical
  evidence report for this run.
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_182.md` — Run 182
  source/test production call-site wiring this run captures
  release-binary evidence for.
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_181.md` — Run 181
  release-binary OnChainGovernance production-surface fixture-policy
  selector evidence (the predecessor whose deferred binary-side
  per-surface wiring Run 182 / 183 close together).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_180.md` — Run 180
  source/test wiring (per-surface composed wrappers + selector +
  banner).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_178.md` — Run 178
  source/test typed verifier.
* `docs/devnet/run_181_onchain_governance_production_surface_release_binary/`
  — release-binary archive Run 183 inherits its harness shape from.
* `crates/qbind-node/src/pqc_onchain_governance_callsite_wiring.rs` —
  Run 182 module (untouched by Run 183).
* `crates/qbind-node/src/pqc_onchain_governance_proof_surface.rs` —
  Run 180 module (untouched by Run 183).
* `crates/qbind-node/src/pqc_onchain_governance_proof.rs` — Run 178
  module (untouched by Run 183).
* `crates/qbind-node/tests/run_182_onchain_governance_production_callsite_wiring_tests.rs`
  — Run 182 source/test corpus exercised by the harness regression
  slice (untouched by Run 183).
* `crates/qbind-node/tests/run_180_onchain_governance_marker_integration_tests.rs`
  — Run 180 source/test corpus exercised by the harness regression
  slice (untouched by Run 183).
