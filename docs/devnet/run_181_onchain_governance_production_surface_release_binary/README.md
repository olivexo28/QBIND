# Run 181 — Release-binary OnChainGovernance production-surface fixture evidence

## Scope

Closes the Run 180-deferred release-binary boundary for the source/test
production marker-decision composition of the Run 178 typed
`OnChainGovernance` proof verifier behind the hidden DevNet/TestNet
disabled-by-default `OnChainGovernanceProofPolicy::AllowFixtureSourceTest`
selector. Run 180 added the new library module
`crates/qbind-node/src/pqc_onchain_governance_proof_surface.rs`
(shared composed helper plus seven per-surface named wrappers), the
hidden CLI flag
`--p2p-trust-bundle-onchain-governance-fixture-allowed`, and the
environment variable
`QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED`. The
production default remains `OnChainGovernanceProofPolicy::Disabled` on
every surface; MainNet peer-driven apply remains the Run 147 FATAL
invariant. Run 180 is source/test only.

Run 181 captures **release-binary production-surface fixture-policy
selector reachability** evidence:

* the real `target/release/qbind-node` binary parses the hidden
  `--p2p-trust-bundle-onchain-governance-fixture-allowed` CLI flag,
  reads the
  `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED`
  environment variable, OR-combines them via
  [`onchain_governance_proof_policy_from_cli_or_env`](
    ../../../crates/qbind-node/src/pqc_onchain_governance_proof_surface.rs)
  inside `crates/qbind-node/src/main.rs`, and emits the
  `[run-180] hidden DevNet/TestNet OnChainGovernance fixture-proof
  policy ARMED (AllowFixtureSourceTest)` banner exactly when armed;
* the production default — neither flag nor env var truthy — emits
  no banner and preserves the
  `OnChainGovernanceProofPolicy::Disabled` production default on
  every surface;
* `qbind-node --help` does not surface the hidden selector flag
  (`hide = true`) and does not surface a `run-180` / `run-181` /
  `onchain-governance-fixture` token;
* the real binary's MainNet peer-driven apply refusal (Run 147 FATAL
  invariant) is unchanged with the selector armed: requesting
  `--print-genesis-hash --network mainnet` with the selector engaged
  emits no `MainNet peer-driven apply ENABLED` token;
* a release-built helper (the Run 179
  `run_179_onchain_governance_proof_release_binary_helper` example,
  reused here because it drives the production library
  `OnChainGovernance` verifier symbols Run 180 wired the per-surface
  wrappers into) exercises the Run 178 / Run 180 acceptance and
  rejection corpus end-to-end in **release mode** through the
  production library symbols
  `verify_onchain_governance_proof`,
  `validate_lifecycle_with_onchain_governance_proof`,
  `compose_onchain_governance_marker_decision`, and the seven
  Run 180 per-surface named wrappers
  (`reload_check_compose_onchain_governance_marker_decision`,
  `reload_apply_compose_onchain_governance_marker_decision`,
  `startup_p2p_trust_bundle_compose_onchain_governance_marker_decision`,
  `sighup_compose_onchain_governance_marker_decision`,
  `local_peer_candidate_check_compose_onchain_governance_marker_decision`,
  `live_inbound_0x05_compose_onchain_governance_marker_decision`,
  `peer_driven_drain_compose_onchain_governance_marker_decision`);
* a source-reachability proof is recorded showing the production-
  source-tree call sites for every selector, every wrapper, and the
  `main.rs` capture site.

## Strict scope (no production-source change)

Per `task/RUN_181_TASK.txt`:

* **Release-binary evidence only.** Run 181 introduces no new
  production module, no new production CLI flag, no new env knob, no
  new schema bump, no new wire shape, no new metric, and no new exit
  code beyond the Run 180 surface. The only new files committed by
  Run 181 are this evidence archive and the harness shell script
  (`scripts/devnet/run_181_onchain_governance_production_surface_release_binary.sh`)
  plus narrow append-only paragraphs in
  `docs/whitepaper/contradiction.md`,
  `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`,
  `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`,
  and `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`.
* **No MainNet apply enablement.** The Run 147 FATAL invariant
  ("MainNet peer-driven apply is unsupported and fail-closed")
  survives Run 181 unchanged; the helper R23 scenario and the
  release-binary R23 capture both reassert it.
* **No real on-chain verifier / bridge / light-client / KMS-HSM /
  validator-set rotation / autonomous apply / apply-on-receipt /
  peer-majority authority** is introduced.
* **No schema / wire / metric drift** beyond the Run 178 additive
  wire shape (`ONCHAIN_GOVERNANCE_PROOF_WIRE_SCHEMA_VERSION = 1`,
  optional sibling field on `GovernanceAuthorityProofWire`) plus the
  Run 180 hidden CLI flag and env var.
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
the Run 153 / 155 / 158 / 172 / 175 / 177 / 179 evidence-archive
convention.

## Reproducibility

```bash
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node \
    --example run_179_onchain_governance_proof_release_binary_helper
bash scripts/devnet/run_181_onchain_governance_production_surface_release_binary.sh
```

`OUTDIR` defaults to this directory. The harness is **idempotent**:
it wipes `logs/`, `data/`, `exit_codes/`, `helper_evidence/`,
`reachability/`, `test_results/`, `scenarios/`, and `grep_summaries/`
on every invocation and re-mints the helper corpus from the
release-built helper. The `summary.txt` line written at the end of
the harness is the canonical verdict.

## Scenario corpus

Mirrors `task/RUN_181_TASK.txt` exactly:

* **A1 — default Disabled rejects** OnChainGovernance proof on
  reload-check (no CLI flag, no env var). Real `qbind-node` emits no
  Run 180 banner; selector observed disabled.
* **A2 — CLI selector** enables `AllowFixtureSourceTest` on
  reload-check; real `qbind-node` emits the
  `[run-180] ... policy ARMED (AllowFixtureSourceTest)` banner.
* **A3 — env selector** enables `AllowFixtureSourceTest` on
  reload-check across truthy variants `{1, true, TRUE, True, yes,
  YES, on, ON}`; falsey variants `{0, false, FALSE, no, off, "",
  garbage}` keep the selector disabled.
* **A4 — CLI selector + reload-apply**, **A5 — env selector +
  reload-apply** — production-surface **selector reachability** is
  captured on the real binary; the corresponding library-level
  acceptance is captured by the release-built helper through
  `reload_apply_compose_onchain_governance_marker_decision`.
* **A6 — TestNet fixture** OnChainGovernance Rotate proof acceptance
  on validation-only surface — captured via the helper's TestNet
  fixture corpus through the production library symbols.
* **A7 — Revoke / EmergencyRevoke** acceptance — captured via the
  helper's A4–A6 lifecycle-action variants.
* **A8 — GenesisBound and EmergencyCouncil** proof-carrying
  behavior unchanged — captured via the helper's R24 round-trip and
  A7 sibling tests.
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
  rejection non-mutating / live-0x05 invalid candidate
  not-propagated. Captured via the helper through the production
  library symbols and the seven per-surface wrappers, plus the
  release-binary R23 MainNet refusal capture.

Per-scenario rc, expected typed outcome, actual typed outcome, and
canonical commitment bytes are written to `helper_evidence/` and
surfaced in `summary.txt` (regenerated each run).

## Honest limitations preserved

* **Verdict is `partial-positive`, not `strongest-positive`.**
  Run 180's binary-side wiring stops at the selector capture site
  in `crates/qbind-node/src/main.rs` (banner emission only). The
  per-surface marker-decision call sites
  (`--p2p-trust-bundle-reload-check`,
  `--p2p-trust-bundle-reload-apply-*`, startup `--p2p-trust-bundle`,
  SIGHUP, `--p2p-trust-bundle-peer-candidate-check`, live `0x05`,
  peer-driven drain coordinator) do **not** yet pass the resolved
  `OnChainGovernanceProofPolicy` down into
  `compose_onchain_governance_marker_decision`. Run 181 captures
  this honestly via `mutation_proof.txt` and identifies the strict
  next integration run that must complete that wiring.
* **No real on-chain governance, no execution, no bridge / light
  client / KMS-HSM / validator-set rotation.** Run 181 is fixture-
  only and selector-reachability-only — exactly as Run 180 declared
  its scope.
* **MainNet peer-driven apply remains refused** under all
  combinations (Run 147 FATAL invariant). R23 captures this on the
  real binary and through the helper.
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
* The Run 178 / 180 / 181 verifier and selector are not surfaced
  via `qbind-node --help` (no flag named
  `p2p-trust-bundle-onchain-governance-fixture-allowed` or
  `onchain-governance` or `run-180` / `run-181` is visible).
* No new schema / wire / metric drift beyond the Run 178 additive
  wire shape and the Run 180 hidden selector.
* No marker write before sequence commit; no sequence write or
  marker write on validation-only surfaces; no `.tmp` residue;
  data dir empty for every release-binary scenario in this run
  (every scenario uses `--print-genesis-hash` which never opens a
  data dir).

## Cross-references

* `task/RUN_181_TASK.txt` — driving spec (acceptance / rejection
  matrix, validation commands, deliverables, honest verdict).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_181.md` — canonical
  evidence report for this run.
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_180.md` — Run 180
  source/test wiring this run captures release-binary evidence
  for.
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_179.md` — Run 179
  release-binary verifier-corpus boundary evidence.
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_178.md` — Run 178
  source/test typed verifier.
* `docs/devnet/run_179_onchain_governance_proof_release_binary/` —
  release-binary archive template Run 181 inherits its harness
  shape from.
* `crates/qbind-node/src/pqc_onchain_governance_proof_surface.rs` —
  Run 180 module (untouched by Run 181).
* `crates/qbind-node/src/pqc_onchain_governance_proof.rs` — Run 178
  module (untouched by Run 181).
* `crates/qbind-node/tests/run_180_onchain_governance_marker_integration_tests.rs`
  — Run 180 source/test corpus exercised by the harness regression
  slice (untouched by Run 181).