# Run 185 — Release-binary OnChainGovernance payload-carrying accepted-proof evidence

## Scope

Closes the Run 184-deferred release-binary boundary for the
source/test OnChainGovernance proof-payload-carrying layer added by
[`crates/qbind-node/src/pqc_onchain_governance_payload_carrying.rs`](
  ../../../crates/qbind-node/src/pqc_onchain_governance_payload_carrying.rs).
Run 184 added the additive optional `onchain_governance_proof`
sibling on the existing v2 ratification sidecar JSON wire (sibling
extracted before the strict
[`qbind_ledger::BundleSigningRatificationV2`](
  ../../../crates/qbind-ledger/src/bundle_signing_ratification.rs)
parse, following the Run 167 `governance_authority_proof` pattern),
the typed
[`OnChainGovernanceProofLoadStatus`](
  ../../../crates/qbind-node/src/pqc_onchain_governance_payload_carrying.rs)
(`Absent` / `Available` / `Malformed`), the path/bytes loaders
[`load_v2_ratification_sidecar_with_onchain_governance_proof_from_path`](
  ../../../crates/qbind-node/src/pqc_onchain_governance_payload_carrying.rs)
and `_from_bytes`, the
typed `OnChainGovernancePayloadCarryingDecisionOutcome` with its
fail-closed `MalformedOnChainGovernanceProofPayload` variant placed
*in front of* every Run 182 named call-site entry, and the seven
`route_loaded_onchain_governance_proof_to_*_callsite_decision`
helpers that bind a parsed status to each Run 182 entry. Run 184 is
source/test only; release-binary accepted-proof evidence is
**this Run 185**.

Run 185 captures **release-binary** evidence that real
`target/release/qbind-node` production payload/context paths can
**carry typed OnChainGovernance fixture proof material into the
Run 182 production call-site wrappers** and accept valid fixture
proofs under the hidden Run 180
`OnChainGovernanceProofPolicy::AllowFixtureSourceTest` selector
(`--p2p-trust-bundle-onchain-governance-fixture-allowed` /
`QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED`):

* a real `target/release/qbind-node` invocation with the hidden
  selector engaged AND a v2 ratification sidecar carrying a typed
  Run 184 `OnChainGovernanceProofWire` sibling reaches the Run 182
  `reload_check_callsite_onchain_governance_marker_decision` /
  `reload_apply_callsite_onchain_governance_marker_decision` named
  entries through the production `--p2p-trust-bundle-reload-check`
  and `--p2p-trust-bundle-reload-apply-path` payload/context paths,
  the `verify_onchain_governance_proof` symbol is reached through
  real production code, and the typed accepted outcome is observed;
* the production default — neither flag nor env var truthy — emits
  no Run 180 banner, preserves the
  `OnChainGovernanceProofPolicy::Disabled` production default on
  every surface, and a v2 sidecar without the additive sibling
  parses byte-for-byte identically to its pre-Run-184 form (A1);
* malformed sibling bytes (non-object, unknown schema-version, empty
  required field, empty proof-bytes) are rejected as a typed
  `OnChainGovernanceProofPayloadParseError` *before* any verifier
  runs, surface-uniformly across all seven Run 182 entries, and
  produce no marker write, no sequence write, no live trust swap,
  no session eviction, and no Run 070 call (R2 / malformed corpus);
* the Run 147 / 148 / 152 FATAL MainNet peer-driven apply refusal
  invariant survives unchanged with the selector armed AND a fully
  valid DevNet fixture proof carried through the Run 184 payload
  layer — the Run 182 peer-driven-drain entry's surface-level
  `MainNetRefused` short-circuit fires ahead of the Run 180
  verifier (R26);
* the release-built helper(s) — the Run 179
  `run_179_onchain_governance_proof_release_binary_helper` for the
  verifier corpus and the new Run 185
  `run_185_onchain_governance_payload_release_binary_helper` for the
  Run 184 payload-carrying / call-site-routing corpus — exercise the
  Run 178 / 180 / 182 / 184 acceptance and rejection corpus
  end-to-end in **release mode** through the production library
  symbols `verify_onchain_governance_proof`,
  `validate_lifecycle_with_onchain_governance_proof`,
  `compose_onchain_governance_marker_decision`, the seven Run 180
  per-surface composed wrappers, the seven Run 182 named call-site
  entries plus `OnChainGovernanceCallsiteContext` and
  `with_onchain_governance_fixture_allowed_selector`, the Run 184
  payload-carrying loaders
  `load_v2_ratification_sidecar_with_onchain_governance_proof_from_*`
  / `parse_optional_onchain_governance_proof_sibling_from_json_value`
  / `callsite_context_with_loaded_onchain_governance_proof`, and
  every `route_loaded_onchain_governance_proof_to_*_callsite_decision`
  helper.

## Strict scope (no production-source change beyond Run 184)

Per `task/RUN_185_TASK.txt`:

* **Release-binary evidence only.** Run 185 introduces no new
  production module, no new production CLI flag, no new env knob,
  no new schema bump, no new wire shape, no new sidecar field, no
  new metric, and no new exit code beyond the Run 178 typed wire
  + Run 180 hidden selector + Run 184 additive optional
  `onchain_governance_proof` sidecar sibling already in the tree.
  The only new files committed by Run 185 are this evidence
  archive, the harness shell script
  [`scripts/devnet/run_185_onchain_governance_payload_release_binary.sh`](
    ../../../scripts/devnet/run_185_onchain_governance_payload_release_binary.sh),
  the release-built helper example
  [`crates/qbind-node/examples/run_185_onchain_governance_payload_release_binary_helper.rs`](
    ../../../crates/qbind-node/examples/run_185_onchain_governance_payload_release_binary_helper.rs),
  and the canonical evidence report
  [`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_185.md`](
    ../QBIND_DEVNET_EVIDENCE_RUN_185.md), plus narrow append-only
  paragraphs in `docs/whitepaper/contradiction.md`,
  `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`,
  `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`,
  and `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`.
* **No MainNet apply enablement.** The Run 147 FATAL invariant
  ("MainNet peer-driven apply is unsupported and fail-closed")
  survives Run 185 unchanged; the helper's R26 scenario and the
  release-binary R26 capture both reassert it on real
  `target/release/qbind-node` even with the selector armed AND a
  fully-valid DevNet fixture proof carried in the v2 ratification
  sidecar via the Run 184 sibling.
* **No real on-chain governance verifier / bridge / light-client /
  KMS-HSM / validator-set rotation / autonomous apply /
  apply-on-receipt / peer-majority authority** is introduced.
* **No schema / wire / metric drift** beyond Run 184's additive
  optional sibling.
* **No marker / sequence-file / trust-bundle core schema change.**
* **Do not weaken Runs 070, 130–184.**
* **No claim of full C4 / C5 closure.**

## What is committed

Only `README.md`, `summary.txt`, and `.gitignore` are tracked. Every
per-run artifact under this directory (`logs/`, `data/`,
`exit_codes/`, `marker_hashes/`, `sequence_hashes/`,
`data_inventories/`, `grep_summaries/`, `reachability/`,
`test_results/`, `fixtures/`, `scenarios/`, `helper_evidence/`,
`helper_corpus/`, `sidecars/`, `provenance.txt`,
`fixture_manifest.txt`, `scenario_assertions.txt`,
`negative_invariants.txt`, `mutation_proof.txt`,
`no_mutation_proof.txt`) contains absolute paths and ephemeral
data and is `.gitignore`d on purpose, matching the Run 153 / 155 /
158 / 172 / 175 / 177 / 179 / 181 / 183 evidence-archive
convention.

## Reproducibility

```bash
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node \
    --example run_179_onchain_governance_proof_release_binary_helper
cargo build --release -p qbind-node \
    --example run_185_onchain_governance_payload_release_binary_helper
bash scripts/devnet/run_185_onchain_governance_payload_release_binary.sh
```

`OUTDIR` defaults to this directory. The harness is **idempotent**:
it wipes `logs/`, `data/`, `exit_codes/`, `helper_evidence/`,
`reachability/`, `test_results/`, `scenarios/`, `sidecars/`, and
`grep_summaries/` on every invocation and re-mints the helper
corpus and the typed-proof-carrying v2 sidecar JSONs from the
release-built helpers. The `summary.txt` line written at the end of
the harness is the canonical verdict; the committed `summary.txt`
is the `NOT-YET-RUN` placeholder canonical archive copy that the
harness overwrites on every invocation.

## Required production surfaces exercised

Per `task/RUN_185_TASK.txt §Required production surfaces`:

* **A. Validation-only:** `--p2p-trust-bundle-reload-check` (the
  preferred validation-only surface) — a real
  `target/release/qbind-node --p2p-trust-bundle-reload-check
  --p2p-trust-bundle-onchain-governance-fixture-allowed
  --p2p-trust-bundle-reload-check-path <sidecar-with-sibling>`
  invocation reaches the Run 182
  `reload_check_callsite_onchain_governance_marker_decision`
  through the production
  `preflight_run_132_validation_only_v2_marker_check` code path,
  the parsed proof from the Run 184 sibling is supplied via
  `OnChainGovernanceCallsiteContext`, and acceptance is observed
  with no marker write and no sequence write.
* **B. Mutating:** process-start
  `--p2p-trust-bundle-reload-apply-path` (the preferred mutating
  surface) — a real `target/release/qbind-node
  --p2p-trust-bundle-reload-apply-path <sidecar-with-sibling>
  --p2p-trust-bundle-onchain-governance-fixture-allowed`
  invocation reaches the Run 182
  `reload_apply_callsite_onchain_governance_marker_decision`
  through the production `preflight_run_134_v2_marker_decision`
  code path, the parsed proof is routed into the call-site
  context, lifecycle validation accepts, and the mutating apply
  succeeds with the Run 055 sequence-before-marker ordering
  preserved.

Also covered by the harness through the release-built helpers
(library-layer release-mode evidence captured for every Run 182
named entry):

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

For surfaces whose existing wire format does not yet carry the
Run 184 sibling end-to-end on a real binary path (live `0x05`
peer-candidate envelope, peer-driven drain inbound payload), the
harness records an honest boundary line and cites the Run 184
source/test carrier coverage for that path; the release helper
exercises every Run 182 named entry through the production
library symbols in release mode.

## Scenario corpus

Mirrors `task/RUN_185_TASK.txt` exactly:

* **A1 — default Disabled preserves legacy/no-proof payload
  compatibility.** No CLI flag, no env var. A v2 ratification
  sidecar without the Run 184 sibling parses byte-for-byte
  identically to its pre-Run-184 form (every Run 182 callsite
  entry short-circuits on `PolicyDisabled` before any verifier
  work runs); a v2 sidecar carrying a fully-valid sibling parses
  the sibling but the policy default keeps the carrier
  short-circuited at `PolicyDisabled` (no
  `OnChainGovernance` acceptance); validation-only non-mutation
  preserved.
* **A2 — CLI selector + reload-check + valid DevNet Rotate
  proof payload.** `--p2p-trust-bundle-onchain-governance-fixture-allowed`
  observed; `onchain_governance_proof` sibling loaded; typed
  `OnChainGovernanceProofWire` parsed; proof routed into the
  Run 182 `reload_check_callsite_` context;
  `verify_onchain_governance_proof` reached; lifecycle validation
  accepts; marker decision accepts; **no marker write, no
  sequence write** (validation-only surface).
* **A3 — env selector + reload-check + valid DevNet Rotate
  proof payload.** Truthy variants `{1, true, TRUE, True, yes,
  YES, on, ON}`; falsey variants keep selector disabled.
* **A4 — CLI selector + reload-apply + valid DevNet Rotate
  proof payload.** Proof payload parse occurs before marker
  decision; OnChainGovernance verifier accepts before
  apply/mutation; lifecycle validation accepts before
  apply/mutation; mutating apply succeeds; **Run 055 sequence
  commit succeeds; v2 marker persists strictly after sequence
  commit**; canonical marker / sequence JSON+SHA before/after
  recorded.
* **A5 — env selector + reload-apply + valid DevNet Rotate
  proof payload.** Same as A4 using env selector.
* **A6 — TestNet fixture Rotate proof through reload-check.**
  Validation-only acceptance; non-mutation preserved.
* **A7 — local peer-candidate-check accepts valid proof.**
  Validation-only; no sequence write; no marker write.
* **A8 — live inbound `0x05` accepts valid proof.** Captured via
  the helper-driven release-mode path through the Run 182
  `live_inbound_0x05_callsite_` entry; the live peer-candidate
  envelope's existing additive sibling field is exercised; if
  the live wire format does not yet carry the typed payload
  end-to-end on a real binary, the boundary is honestly recorded
  and Run 184 source/test coverage is cited.
* **A9 — GenesisBound and EmergencyCouncil unchanged.** Helper
  R24 round-trip and A7 sibling tests confirm those proof modes
  do not enter the OnChainGovernance call-site path.
* **R1–R26 — full rejection matrix.** Selector unset / malformed
  payload / wrong environment / wrong chain / wrong genesis /
  wrong authority root / wrong governance domain / wrong
  proposal digest / wrong proposal outcome / wrong lifecycle
  action / wrong candidate digest / wrong authority-domain
  sequence / expired / replayed / quorum / threshold / invalid
  proof bytes / unsupported proof suite / local-operator-config
  alone / peer-majority alone / proof-valid-lifecycle-invalid /
  lifecycle-valid-proof-invalid / validation-only rejection
  non-mutating / mutating rejection non-mutating / live-`0x05`
  invalid candidate not propagated / MainNet peer-driven apply
  refused with armed selector AND fully-valid DevNet fixture
  proof carried in payload. Captured via the release-built
  helpers through every Run 182 named callsite entry plus the
  release-binary R26 MainNet refusal capture on real
  `target/release/qbind-node`.

Per-scenario rc, expected typed outcome, actual typed outcome,
sidecar JSON path + SHA-256, and (where applicable) marker /
sequence JSON+SHA before/after are written to `helper_evidence/`
and surfaced in `summary.txt` (regenerated each run).

## Honest limitations preserved

* **Default policy remains `OnChainGovernanceProofPolicy::Disabled`
  on every surface.** The hidden `AllowFixtureSourceTest` selector
  is DevNet/TestNet fixture-only, hidden behind the Run 180
  `--p2p-trust-bundle-onchain-governance-fixture-allowed`
  (`hide = true`) CLI flag and the
  `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED`
  environment variable, and never on by default.
* **No real on-chain governance / no real on-chain proof
  verifier / no governance execution engine / no bridge /
  light-client / KMS-HSM / validator-set rotation / autonomous
  apply / apply-on-receipt / peer-majority authority.** Run 185 is
  fixture-only release-binary evidence — the Run 178 fixture proof
  suite `ONCHAIN_GOVERNANCE_PROOF_SUITE_FIXTURE_MOCK_V1 = 0xA1`
  is a deterministic mock commitment over the bound fields and is
  **not** a real on-chain verifier; the reserved suite id
  `ONCHAIN_GOVERNANCE_PROOF_SUITE_RESERVED_PRODUCTION = 0xA2` is
  rejected as `UnsupportedGovernanceProofSuite`.
* **MainNet peer-driven apply remains refused** under all
  combinations (Run 147 FATAL invariant). R26 captures this on
  real `target/release/qbind-node` AND through the helper,
  including the Run 182 peer-driven-drain callsite entry's
  surface-level `MainNetRefused` short-circuit layered ahead of
  the Run 180 verifier.
* **No claim of full C4 / C5 closure.** OnChainGovernance
  execution, governance program integration, real on-chain proof
  verification, and validator-set rotation remain out of scope.

## Negative invariants

Captured in `negative_invariants.txt` (regenerated each run).
Highlights:

* No `DummySig` / `DummyKem` / `DummyAead` symbol in any captured
  log.
* No `fallback to --p2p-trusted-root` and no peer-majority
  authority claim.
* No autonomous apply / apply-on-receipt / governance-execution
  language in helper or `qbind-node` output.
* The Run 178 / 180 / 181 / 182 / 183 / 184 verifier and selector
  are not surfaced via `qbind-node --help` (no flag named
  `p2p-trust-bundle-onchain-governance-fixture-allowed` or
  `onchain-governance` or `run-180` / `run-181` / `run-182` /
  `run-183` / `run-184` / `run-185` is visible).
* No new schema / wire / metric drift beyond the Run 184 additive
  optional sibling and the Run 180 hidden selector.
* No marker write before sequence commit; no sequence write or
  marker write on validation-only surfaces; no `.tmp` residue;
  no fallback to `--p2p-trusted-root`.

## Cross-references

* `task/RUN_185_TASK.txt` — driving spec (acceptance / rejection
  matrix, validation commands, deliverables, honest verdict).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_185.md` — canonical
  evidence report for this run.
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_184.md` — Run 184
  source/test OnChainGovernance proof-carrying payload/context
  layer this run captures release-binary evidence for.
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_183.md` — Run 183
  release-binary OnChainGovernance production call-site evidence
  for the Run 182 wiring.
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_182.md` — Run 182
  source/test production call-site wiring.
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_181.md` — Run 181
  release-binary OnChainGovernance production-surface
  fixture-policy selector evidence.
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_180.md` — Run 180
  source/test wiring (per-surface composed wrappers + selector +
  banner).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_179.md` — Run 179
  release-binary verifier corpus boundary evidence.
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_178.md` — Run 178
  source/test typed verifier.
* `docs/devnet/run_183_onchain_governance_callsite_release_binary/`
  — release-binary archive Run 185 inherits its harness shape
  from.
* `crates/qbind-node/src/pqc_onchain_governance_payload_carrying.rs`
  — Run 184 module exercised in release mode by Run 185
  (untouched by Run 185).
* `crates/qbind-node/src/pqc_onchain_governance_callsite_wiring.rs`
  — Run 182 module (untouched by Run 185).
* `crates/qbind-node/src/pqc_onchain_governance_proof_surface.rs`
  — Run 180 module (untouched by Run 185).
* `crates/qbind-node/src/pqc_onchain_governance_proof.rs` —
  Run 178 module (untouched by Run 185).
* `crates/qbind-node/tests/run_184_onchain_governance_payload_carrying_tests.rs`
  — Run 184 source/test corpus exercised by the harness
  regression slice (untouched by Run 185).
* `crates/qbind-node/tests/run_182_onchain_governance_production_callsite_wiring_tests.rs`
  — Run 182 source/test corpus exercised by the harness
  regression slice (untouched by Run 185).
* `crates/qbind-node/tests/run_180_onchain_governance_marker_integration_tests.rs`
  — Run 180 source/test corpus exercised by the harness
  regression slice (untouched by Run 185).
